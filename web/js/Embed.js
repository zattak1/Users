// ===========================================================================
// Q.Users.Embed — parent-side embed bridge
// ===========================================================================
//
// Loaded by a third-party host page to mount a Qbix iframe and talk to it.
// All communication between the two documents goes through postMessage; this
// file is the parent side of that conversation.
//
// What this provides:
//   Q.Users.Embed({url, container, ...})     create and register an iframe
//   Q.Users.Embed.stream({publisherId, ...}) convenience for the /embed route
//   Q.Users.Embed.call(iframe, method, ...)  postMessage RPC with timeout
//   Q.Users.Embed.on/off(iframe, name, cb)   subscribe to named iframe events
//   Q.Users.Embed.destroy/remove(iframe)     explicit teardown of an iframe
//   Recovery-key persistence in the parent's IndexedDB (opt-out via
//     recoveryKeyStorage: false)
//   Click interception on same-origin links: mints a bridge token through
//     Users.bridge.mint, appends Q.Users.intent, then top-level navigates.
//
// Trust model:
//   Iframe is first-party Qbix origin and is trusted for correctness. The
//   PARENT is untrusted for AVAILABILITY of the recovery key: it may delete,
//   withhold, or lie about what's stored. The server's origin + signature
//   checks are what actually gate recovery; the key stored here only ever
//   speeds up a legitimate user on the same device. Nothing in this file
//   makes a security decision on the host page's behalf.
//
// Hardening in this build that's easy to miss on a read:
//   - UUIDs come from window.crypto; we throw rather than fall back to
//     Math.random, because qid is used in trust checks.
//   - Message dispatch requires BOTH source-window identity and origin
//     match (sameDocument). A plain origin check is not enough.
//   - Every iframe load bumps a generation counter and cancels pending
//     callbacks, so a reply posted to a previous page can't resolve against
//     a call made to the current one.
//   - Resize payloads are clamped to MAX_AUTO_HEIGHT.
//   - allowedMethods, when set, is an opt-in whitelist for Embed.call.
//
// Usage:
//   <script src="https://qbix.org/Q/plugins/Users/Embed.js"></script>
// ===========================================================================

(function (window, document) {
    'use strict';
    var Q = window.Q = window.Q || {};
    Q.Users = Q.Users || {};

    // Minimal logger shims if Q.js hasn't loaded ahead of this file.
    if (!Q.log) Q.log = function (msg) { if (window.console) console.log(msg); };
    if (!Q.warn) Q.warn = function (msg) { if (window.console && console.warn) console.warn(msg); };

    // -----------------------------------------------------------------------
    // Random identifiers
    // -----------------------------------------------------------------------
    // qid is used in origin-adjacent trust checks (pending-callback matching,
    // event-handler keying), so we insist on a cryptographically strong source
    // and throw loudly rather than fall back to Math.random the way the old
    // code did. That's a security choice, not a portability one.
    function uuid() {
        if (!window.crypto || !window.crypto.getRandomValues) throw new Error('Secure random generator unavailable');
        if (window.crypto.randomUUID) return window.crypto.randomUUID();
        var b = new Uint8Array(16);
        window.crypto.getRandomValues(b);
        return Array.prototype.map.call(b, function (n) { return ('0' + n.toString(16)).slice(-2); }).join('');
    }
    if (!Q.uuid) Q.uuid = uuid;

    // -----------------------------------------------------------------------
    // Origin detection
    // -----------------------------------------------------------------------
    // originOf restricts to HTTP(S) so that data:, blob:, javascript:, file:,
    // and anything else can never become an "expected origin" we'd later use
    // as a target for postMessage.
    function originOf(url) {
        try {
            var u = new URL(url, window.location.href);
            return /^https?:$/.test(u.protocol) ? u.origin : null;
        } catch (e) { return null; }
    }

    // document.currentScript captures this file's own <script> at parse time;
    // detectOrigin falls back to scanning tags for an Embed.js or Q.js if the
    // script was injected dynamically (currentScript null in that case).
    var script = document.currentScript;
    function detectOrigin() {
        if (script && script.src) return originOf(script.src);
        var scripts = document.getElementsByTagName('script');
        for (var i = scripts.length - 1; i >= 0; --i) {
            if (/\/(?:Embed|Q)\.js(?:[?#]|$)/.test(scripts[i].src || '')) return originOf(scripts[i].src);
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // IndexedDB wrapper
    // -----------------------------------------------------------------------
    // Per-dbName open/close with completion-semantics callbacks. We deliberately
    // leave an existing Q.IndexedDB alone (another module may have installed a
    // richer one). Writes use tx.oncomplete so the callback fires after commit,
    // not merely after the put request was accepted -- the earlier version here
    // acknowledged writes early and could lose data on tab close.
    var IDB = Q.IndexedDB || (Q.IndexedDB = {});
    if (!IDB.open) IDB.open = function (dbName, storeName, keyPath, callback) {
        if (!window.indexedDB) return callback(new Error('No IndexedDB'));
        var req;
        try { req = window.indexedDB.open(dbName, 1); }
        catch (e) { return callback(e); }
        req.onupgradeneeded = function () {
            if (!req.result.objectStoreNames.contains(storeName)) req.result.createObjectStore(storeName, { keyPath: keyPath });
        };
        req.onerror = function () { callback(req.error || new Error('IndexedDB open failed')); };
        req.onsuccess = function () { callback(null, req.result); };
    };
    if (!IDB.put) IDB.put = function (db, store, id, key, cb) {
        try {
            var tx = db.transaction(store, 'readwrite');
            tx.objectStore(store).put({ id: id, key: key });
            // tx.oncomplete fires after the write actually commits, not just
            // after the request is queued. This is the correct ack point.
            tx.oncomplete = function () { if (cb) cb(null, true); };
            tx.onerror = function () { if (cb) cb(tx.error); };
            tx.onabort = function () { if (cb) cb(tx.error || new Error('IndexedDB aborted')); };
        } catch (e) { if (cb) cb(e); }
    };
    if (!IDB.get) IDB.get = function (db, store, id, cb) {
        try {
            var tx = db.transaction(store, 'readonly');
            var req = tx.objectStore(store).get(id);
            req.onsuccess = function () { cb(null, req.result); };
            req.onerror = function () { cb(req.error || new Error('IndexedDB read failed')); };
        } catch (e) { cb(e); }
    };
    if (!IDB.del) IDB.del = function (db, store, id, cb) {
        try {
            var tx = db.transaction(store, 'readwrite');
            tx.objectStore(store).delete(id);
            tx.oncomplete = function () { if (cb) cb(null, true); };
            tx.onerror = function () { if (cb) cb(tx.error); };
            tx.onabort = function () { if (cb) cb(tx.error || new Error('IndexedDB aborted')); };
        } catch (e) { if (cb) cb(e); }
    };

    // -----------------------------------------------------------------------
    // Module state
    // -----------------------------------------------------------------------
    // Null-prototype objects: no inherited keys, no __proto__ pollution hazard.
    var iframes = Object.create(null);         // qid -> iframe element
    var pending = Object.create(null);         // call id -> pending entry
    var eventHandlers = Object.create(null);   // "qid:name" -> [callback, ...]
    var originalOrigin = detectOrigin();

    // Upper bound on a parent-side autoHeight assignment. A hostile iframe
    // could otherwise force a huge layout by posting an absurd resize payload.
    var MAX_AUTO_HEIGHT = 100000;

    // -----------------------------------------------------------------------
    // Internal helpers (identity, validation, lifecycle)
    // -----------------------------------------------------------------------

    // Is this iframe still the one the registry knows under its qid? Guards
    // against calls against iframes that were destroyed or replaced.
    function isRegistered(iframe) {
        return iframe && iframe.qid && iframes[iframe.qid] === iframe;
    }

    // Strict identity check used on every incoming message: BOTH the source
    // Window and the origin must match the registered iframe. The earlier
    // version accepted a message if origin matched OR a known qid appeared
    // anywhere in the payload -- that second branch let any frame that learned
    // a qid (from a logged URL, a leaked DOM, anything) inject messages. We
    // require both so a cross-origin frame can't forge return values.
    function sameDocument(iframe, source, origin) {
        return isRegistered(iframe) && iframe.contentWindow === source && iframe.origin === origin;
    }

    // Structural shape check on a recovery key before we accept it for
    // storage: ECDSA P-256, non-extractable private half, 'sign' usage.
    // This is NOT a cryptographic integrity check -- a compromised iframe
    // could postMessage a plain object matching this shape. The actual
    // cryptographic guarantee comes from the iframe creating the key
    // non-extractable in the first place; we check the shape so garbage
    // or extractable keys are refused.
    function validRecoveryKey(key) {
        return !!(key && key.privateKey && key.publicKey &&
            key.privateKey.type === 'private' && key.privateKey.extractable === false &&
            key.privateKey.algorithm && key.privateKey.algorithm.name === 'ECDSA' &&
            key.privateKey.algorithm.namedCurve === 'P-256' &&
            key.privateKey.usages && key.privateKey.usages.indexOf('sign') !== -1 &&
            key.publicKey.type === 'public');
    }

    // Open-use-close wrapper. Callers always close the db in their own
    // completion step so we don't hold an open handle between operations.
    function withDb(iframe, callback) {
        IDB.open(iframe.dbName, 'keys', 'id', function (err, db) {
            if (err || !db) return callback(err || new Error('IndexedDB unavailable'));
            callback(null, db);
        });
    }

    // Deliver a recovery-related message to the iframe, origin-targeted so
    // it can't be received by whatever happens to be loaded if the iframe
    // was just navigated elsewhere.
    function postRecovery(iframe, type, key) {
        if (!isRegistered(iframe) || !iframe.contentWindow) return;
        try {
            iframe.contentWindow.postMessage({
                id: iframe.qid,
                type: type,
                payload: { recoveryKey: key || null }
            }, iframe.origin);
        } catch (e) { Q.warn('Q.Users.Embed recovery postMessage failed: ' + e); }
    }

    // Reject all callbacks whose response could still arrive but would be
    // meaningless: iframe navigated away, iframe was destroyed. Called from
    // the load handler and from Embed.destroy.
    function cancelPending(iframe, message) {
        Object.keys(pending).forEach(function (id) {
            var p = pending[id];
            if (p.iframe !== iframe) return;
            delete pending[id];
            clearTimeout(p.timeout);
            if (p.callback) p.callback(new Error(message));
        });
    }

    // -----------------------------------------------------------------------
    // Embed() — iframe constructor and registry
    // -----------------------------------------------------------------------
    /**
     * Create (or wrap) an iframe pointed at a Qbix origin and register it
     * with the bridge. Returns the iframe element with Qbix-side state
     * (qid, origin, dbName, generation, options) attached.
     *
     * @method Embed
     * @param {Object|String} opts  If a string, treated as {url: opts}.
     * @param {String}   [opts.url]       Qbix URL to load. Mutually exclusive
     *                                    with opts.html.
     * @param {String}   [opts.html]      Inline HTML (goes into srcdoc, or a
     *                                    data: URL fallback). When used,
     *                                    opts.origin MUST be set explicitly
     *                                    because the iframe has no URL.
     * @param {String}   [opts.origin]    Explicit expected origin (needed
     *                                    when html is used).
     * @param {Element}  [opts.container] Parent to append the iframe to.
     * @param {HTMLIFrameElement} [opts.iframe] Reuse an existing iframe
     *                                    rather than creating one.
     * @param {String}   [opts.id]        Caller-chosen qid. Must not already
     *                                    be registered.
     * @param {String}   [opts.width='100%']
     * @param {String}   [opts.height='480px']
     * @param {String}   [opts.border='0']
     * @param {String}   [opts.sandbox]   Override default sandbox tokens.
     * @param {String}   [opts.dbName]    IndexedDB name for recovery key
     *                                    storage; derived from origin by
     *                                    default.
     * @param {Boolean}  [opts.recoveryKeyStorage=true] Opt out by passing
     *                                    false; the bridge then ignores
     *                                    recoveryKey.* messages entirely.
     * @param {Array}    [opts.allowedMethods] Whitelist of method names
     *                                    Embed.call will accept; null means
     *                                    no restriction.
     * @param {Boolean}  [opts.autoHeight=true]  Apply Embed.resize payloads
     *                                    to iframe.style.height. Clamped to
     *                                    MAX_AUTO_HEIGHT.
     * @param {Function} [opts.onReady]   Fired once, on the first ready
     *                                    message. The callback property is
     *                                    cleared after it fires, so a
     *                                    reload won't fire it again unless
     *                                    the host reassigns it.
     * @param {Function} [opts.onError]   Fired on every Embed.error.
     * @return {HTMLIFrameElement}
     */
    function Embed(opts) {
        if (typeof opts === 'string') opts = { url: opts };
        opts = opts || {};
        var iframe = opts.iframe || document.createElement('iframe');
        var html = opts.html || '';
        var url = opts.url || (iframe.getAttribute && iframe.getAttribute('src')) || '';
        var origin = opts.origin ? originOf(opts.origin) : (html ? null : originOf(url));
        if (!origin) throw new Error('Q.Users.Embed requires an HTTP(S) iframe URL or explicit origin');
        if (opts.id && Object.prototype.hasOwnProperty.call(iframes, opts.id)) throw new Error('Duplicate iframe id');
        var id = opts.id || uuid();
        if (Object.prototype.hasOwnProperty.call(iframes, id)) throw new Error('Duplicate iframe id');
        // allow-same-origin is in the sandbox default because the iframe needs
        // its own Qbix origin's cookies, IndexedDB, and storage to function at
        // all. In combination with allow-scripts this is effectively no
        // sandbox for the iframe's own origin -- that's the intended posture,
        // since the iframe IS trusted first-party code. The sandbox still
        // keeps the embed out of the parent's DOM and cross-origin storage.
        if (!iframe.hasAttribute('sandbox')) iframe.setAttribute('sandbox', opts.sandbox ||
            'allow-scripts allow-forms allow-popups allow-same-origin allow-storage-access-by-user-activation');
        // Enables the Storage Access API inside a sandboxed iframe (some
        // browsers require this permission token to grant third-party cookies
        // after a user gesture).
        if (!iframe.hasAttribute('allow')) iframe.setAttribute('allow', 'storage-access');
        iframe.style.width = opts.width || '100%';
        iframe.style.height = opts.height || '480px';
        iframe.style.border = opts.border || '0';
        iframe.qid = id;
        iframe.origin = origin;
        iframe.dbName = opts.dbName || 'Q.Users.Embed.' + origin.replace(/[^a-z0-9]/gi, '_');
        iframe.recoveryKeyStorage = opts.recoveryKeyStorage !== false;
        iframe.allowedMethods = opts.allowedMethods || null;
        iframe.autoHeight = opts.autoHeight !== false;
        iframe.onReady = typeof opts.onReady === 'function' ? opts.onReady : null;
        iframe.onError = typeof opts.onError === 'function' ? opts.onError : null;
        // Incremented on every load event (including the first). Pending
        // callbacks captured a snapshot of this value; a reply whose
        // generation no longer matches is discarded as stale. This is what
        // defends against a response from a previous page resolving against
        // a call made to the current one.
        iframe._embedGeneration = 0;
        iframes[id] = iframe;
        iframe.addEventListener('load', function () {
            if (!isRegistered(iframe)) return;
            iframe._embedGeneration++;
            cancelPending(iframe, 'iframe navigated');
            // Only send key to iframe when the iframe's current origin is still expected.
            // postMessage targetOrigin prevents delivery to a different origin.
            Embed._restoreKey(id);
        });
        if (html) {
            if ('srcdoc' in iframe) iframe.srcdoc = html;
            else iframe.src = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
        } else if (opts.url) iframe.src = opts.url;
        if (opts.container && opts.container.appendChild) opts.container.appendChild(iframe);
        if (!Embed._listenerAdded) {
            window.addEventListener('message', Embed._onMessage);
            Embed._listenerAdded = true;
        }
        return iframe;
    }
    Embed.origin = originalOrigin;
    Embed.iframes = iframes;
    Embed._pending = pending;
    Embed._eventHandlers = eventHandlers;
    Embed._callTimeoutMs = 5000;
    Embed._listenerAdded = false;

    // -----------------------------------------------------------------------
    // Conveniences and event subscription
    // -----------------------------------------------------------------------

    /**
     * Create a stream embed iframe pointing at the Streams/embed route.
     * Convenience wrapper over Embed(); same options plus publisherId and streamName.
     */
    Embed.stream = function (opts) {
        if (!opts || !opts.publisherId || !opts.streamName) {
            throw new Error('Q.Users.Embed.stream requires publisherId and streamName');
        }
        if (!Embed.origin) {
            throw new Error('Q.Users.Embed.stream: Qbix origin not detected; set script src or opts.origin');
        }
        opts.url = Embed.origin + '/embed/'
            + encodeURIComponent(opts.publisherId)
            + '/' + encodeURIComponent(opts.streamName);
        return Embed(opts);
    };

    /** Subscribe to a named event posted by this iframe. */
    Embed.on = function (iframe, name, cb) {
        if (!isRegistered(iframe) || typeof name !== 'string' || typeof cb !== 'function') return;
        var key = iframe.qid + ':' + name;
        (eventHandlers[key] = eventHandlers[key] || []).push(cb);
    };

    /** Unsubscribe; omit cb to drop all handlers for name on this iframe. */
    Embed.off = function (iframe, name, cb) {
        if (!isRegistered(iframe) || typeof name !== 'string') return;
        var key = iframe.qid + ':' + name;
        var arr = eventHandlers[key];
        if (!arr) return;
        if (!cb) { delete eventHandlers[key]; return; }
        for (var i = arr.length - 1; i >= 0; --i) if (arr[i] === cb) arr.splice(i, 1);
        if (!arr.length) delete eventHandlers[key];
    };

    // Drop every handler registered for a destroyed iframe's qid. Called
    // from Embed.destroy before we remove the iframe from the registry.
    function clearHandlers(qid) {
        var prefix = qid + ':';
        Object.keys(eventHandlers).forEach(function (k) {
            if (k.indexOf(prefix) === 0) delete eventHandlers[k];
        });
    }

    // -----------------------------------------------------------------------
    // Embed.call — postMessage RPC to the iframe
    // -----------------------------------------------------------------------
    /**
     * Call a method in the iframe and receive a response. The iframe side
     * registers handlers under Q.Users.Embed.handlers[method]; this call
     * posts {type: 'Q.Users.Embed.call', id, method, params} and resolves
     * when the iframe replies with {type: 'Q.Users.Embed.return', id, ...}.
     *
     * Each pending entry captures the source window, origin, and generation
     * at call time. The response matcher insists on all three plus the id,
     * so a stale reply or a message from a different document never
     * resolves a live call.
     *
     * @method call
     * @param {HTMLIFrameElement} iframe
     * @param {String}   method
     * @param {Object}   [params]   Also accepted as the callback slot for
     *                              `.call(iframe, method, callback)`.
     * @param {Function} [callback] (err, result). Required in practice;
     *                              defaults to a no-op so a missing one
     *                              doesn't throw.
     */
    Embed.call = function (iframe, method, params, callback) {
        if (typeof params === 'function') { callback = params; params = {}; }
        callback = typeof callback === 'function' ? callback : function () {};
        if (!isRegistered(iframe) || !iframe.contentWindow) return callback(new Error('Unregistered iframe'));
        if (typeof method !== 'string' || !method) return callback(new Error('Invalid method'));
        // allowedMethods, when set, restricts which methods the host may
        // invoke -- the whitelist is opt-in per iframe.
        if (iframe.allowedMethods && iframe.allowedMethods.indexOf(method) === -1) return callback(new Error('Method not allowed'));
        var id = uuid();
        var p = { iframe: iframe, source: iframe.contentWindow, origin: iframe.origin,
            generation: iframe._embedGeneration, callback: callback };
        pending[id] = p;
        p.timeout = setTimeout(function () {
            if (pending[id] !== p) return;
            delete pending[id];
            callback(new Error('Q.Users.Embed.call ' + method + ' timed out'));
        }, Embed._callTimeoutMs);
        try {
            iframe.contentWindow.postMessage({ type: 'Q.Users.Embed.call', id: id,
                method: method, params: params || {} }, iframe.origin);
        } catch (e) {
            clearTimeout(p.timeout);
            delete pending[id];
            callback(e);
        }
    };

    // -----------------------------------------------------------------------
    // Embed._onMessage — single window-level listener
    // -----------------------------------------------------------------------
    // Shape:
    //   { type: 'Q.Users.Embed.return',          id, result?, error? }
    //   { type: 'Q.Users.Embed.ready',           payload }
    //   { type: 'Q.Users.Embed.error',           payload }
    //   { type: 'Q.Users.Embed.resize',          payload: {height} }
    //   { type: 'Q.Users.Embed.event',           payload: {name, data} }
    //   { type: 'Q.Users.recoveryKey.generated', payload: {recoveryKey} }
    //   { type: 'Q.Users.recoveryKey.cleared'   }
    //   { type: 'Q.Users.recoveryKey.request'   }
    //
    // Every branch first resolves the sender to a registered iframe via
    // sameDocument(). A message that doesn't match a known same-window +
    // same-origin iframe is dropped silently.
    Embed._onMessage = function (ev) {
        var data = ev.data;
        if (!data || typeof data !== 'object' || typeof data.type !== 'string') return;
        var iframe = null;
        Object.keys(iframes).some(function (id) {
            if (sameDocument(iframes[id], ev.source, ev.origin)) { iframe = iframes[id]; return true; }
            return false;
        });
        if (!iframe) return;
        if (data.type === 'Q.Users.Embed.return') {
            if (typeof data.id !== 'string') return;
            var p = pending[data.id];
            // Four-way match: a pending entry must name THIS iframe, the
            // source window must still be the one we called into, the origin
            // must still match, and the generation must be the one that was
            // current when the call was issued. Anything else is stale.
            if (!p || p.iframe !== iframe || p.source !== ev.source || p.origin !== ev.origin ||
                p.generation !== iframe._embedGeneration) return;
            clearTimeout(p.timeout);
            delete pending[data.id];
            p.callback(data.error ? new Error(String(data.error)) : null, data.result);
            return;
        }
        if (data.type === 'Q.Users.Embed.ready') {
            if (typeof iframe.onReady === 'function') {
                // Fire-once semantics. A reload posts ready again, but we
                // don't re-fire unless the host re-assigns iframe.onReady.
                var readyCb = iframe.onReady;
                iframe.onReady = null;
                try { readyCb(iframe, data.payload || {}); }
                catch (e) { Q.warn('Q.Users.Embed.ready handler threw: ' + e); }
            }
            return;
        }
        if (data.type === 'Q.Users.Embed.error') {
            if (typeof iframe.onError === 'function') {
                try { iframe.onError(iframe, data.payload || {}); }
                catch (e) { Q.warn('Q.Users.Embed.error handler threw: ' + e); }
            }
            return;
        }
        if (data.type === 'Q.Users.Embed.resize') {
            // Clamp the height before assigning. A hostile iframe could
            // otherwise request a huge layout by posting an absurd number;
            // isFinite + range check are the belt and MAX_AUTO_HEIGHT the
            // suspenders.
            if (iframe.autoHeight && data.payload
                && typeof data.payload.height === 'number'
                && isFinite(data.payload.height)
                && data.payload.height > 0
                && data.payload.height <= MAX_AUTO_HEIGHT) {
                iframe.style.height = Math.ceil(data.payload.height) + 'px';
            }
            return;
        }
        if (data.type === 'Q.Users.Embed.event') {
            if (!data.payload || typeof data.payload.name !== 'string') return;
            var arr = eventHandlers[iframe.qid + ':' + data.payload.name];
            if (!arr) return;
            // Snapshot arr before iterating so a handler that unsubscribes
            // itself mid-fire doesn't skip a sibling.
            arr.slice().forEach(function (cb) {
                try { cb(data.payload.data, iframe); }
                catch (e) { Q.warn('Q.Users.Embed.event handler threw: ' + e); }
            });
            return;
        }
        // Recovery-key channel: opt-in per iframe, off by default when the
        // host passes recoveryKeyStorage: false. This block is below the
        // generic lifecycle messages so ready/error/resize/event are always
        // delivered, even when recovery storage is disabled.
        if (!iframe.recoveryKeyStorage) return;
        if (data.type === 'Q.Users.recoveryKey.generated') {
            if (!data.payload || !validRecoveryKey(data.payload.recoveryKey)) {
                Q.warn('Q.Users.Embed: rejected invalid or extractable recovery key');
                return;
            }
            Embed._storeKey(iframe.qid, 'recoveryKey', data.payload.recoveryKey);
        } else if (data.type === 'Q.Users.recoveryKey.cleared') {
            Embed._deleteKey(iframe.qid, 'recoveryKey');
        } else if (data.type === 'Q.Users.recoveryKey.request') {
            // Capture the generation now; the read is async and we only
            // want to answer if the iframe is still the same document that
            // asked.
            var generation = iframe._embedGeneration;
            withDb(iframe, function (err, db) {
                if (err) return postRecovery(iframe, 'Q.Users.recoveryKey.recover', null);
                IDB.get(db, 'keys', 'recoveryKey', function (err2, record) {
                    if (isRegistered(iframe) && generation === iframe._embedGeneration)
                        postRecovery(iframe, 'Q.Users.recoveryKey.recover', !err2 && record && validRecoveryKey(record.key) ? record.key : null);
                    if (db.close) db.close();
                });
            });
        }
    };

    // -----------------------------------------------------------------------
    // Recovery-key storage
    // -----------------------------------------------------------------------

    Embed._storeKey = function (id, keyId, keyObj) {
        var iframe = iframes[id];
        if (!iframe || !iframe.recoveryKeyStorage || !validRecoveryKey(keyObj)) return;
        withDb(iframe, function (err, db) {
            if (err) return Q.warn('Q.Users.Embed: key storage unavailable: ' + err);
            IDB.put(db, 'keys', keyId, keyObj, function (err2) {
                if (err2) Q.warn('Q.Users.Embed: key storage failed: ' + err2);
                if (db.close) db.close();
            });
        });
    };
    Embed._deleteKey = function (id, keyId) {
        var iframe = iframes[id];
        if (!iframe) return;
        withDb(iframe, function (err, db) {
            if (err) return;
            IDB.del(db, 'keys', keyId, function () { if (db.close) db.close(); });
        });
    };
    // Called from the load handler to push the stored key back to the iframe
    // after it reloads. Generation check matches the _onMessage pattern:
    // between the IDB read and the postMessage, the iframe might have been
    // navigated again -- don't deliver a key to a stale document.
    Embed._restoreKey = function (id) {
        var iframe = iframes[id];
        if (!iframe || !iframe.recoveryKeyStorage) return;
        var generation = iframe._embedGeneration;
        withDb(iframe, function (err, db) {
            if (err) return;
            IDB.get(db, 'keys', 'recoveryKey', function (err2, record) {
                if (isRegistered(iframe) && generation === iframe._embedGeneration &&
                    !err2 && record && validRecoveryKey(record.key)) {
                    postRecovery(iframe, 'Q.Users.recoveryKey.restored', record.key);
                }
                if (db.close) db.close();
            });
        });
    };

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    Embed._findIframeForOrigin = function (origin) {
        var ids = Object.keys(iframes);
        for (var i = 0; i < ids.length; i++) {
            var iframe = iframes[ids[i]];
            if (iframe.contentWindow && iframe.origin === origin) return iframe;
        }
        return null;
    };

    /**
     * Deregister an iframe. Pending callbacks reject with 'iframe destroyed',
     * event handlers for this qid are cleared, and future messages from the
     * iframe are dropped (sameDocument no longer resolves it). The DOM node
     * is left in place -- use remove() to also detach it.
     *
     * @method destroy
     * @param {HTMLIFrameElement} iframe
     * @return {Boolean} true if the iframe was registered
     */
    Embed.destroy = function (iframe) {
        if (!isRegistered(iframe)) return false;
        cancelPending(iframe, 'iframe destroyed');
        clearHandlers(iframe.qid);
        delete iframes[iframe.qid];
        return true;
    };

    /**
     * Deregister AND detach the iframe from the DOM. Use this for cleanup
     * when the embed is done; use destroy() when you want to keep the
     * element around (e.g. to replace its src with a new embed).
     *
     * @method remove
     * @param {HTMLIFrameElement} iframe
     * @return {Boolean} true if the iframe was registered
     */
    Embed.remove = function (iframe) {
        if (!isRegistered(iframe)) return false;
        Embed.destroy(iframe);
        if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
        return true;
    };

    // -----------------------------------------------------------------------
    // Click interception — bridge-token minting on same-origin links
    // -----------------------------------------------------------------------
    // When a link on the host page points at the Qbix origin we recognize,
    // mint a short-lived bridge token through the iframe and append it as
    // Q.Users.intent before top-level navigating. This lets the Qbix side
    // recognize the arriving user as the same session that was logged into
    // the iframe, without the host having to proxy anything.
    //
    // Skipped: modifier-key clicks (user wants a new window), download
    // links, links already carrying an intent, and non-self/non-top targets
    // (new tab, named frame -- those aren't top-level navigations).
    Embed._onClick = function (ev) {
        if (ev.defaultPrevented || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey || ev.button !== 0) return;
        var a = ev.target;
        while (a && a !== document.body) {
            if (a.tagName === 'A' && a.href) break;
            a = a.parentNode;
        }
        if (!a || a.tagName !== 'A' || !a.href || !Embed.origin) return;
        if (a.hasAttribute('download') || a.getAttribute('data-qbix-bridge') === 'false') return;
        if (a.target && a.target !== '_self' && a.target !== '_top') return;
        var u;
        try { u = new URL(a.href); } catch (e) { return; }
        if (u.origin !== Embed.origin || u.searchParams.has('Q.Users.intent')) return;
        var iframe = Embed._findIframeForOrigin(Embed.origin);
        if (!iframe) return;
        ev.preventDefault();
        var href = a.href;
        // If the mint fails, fall back to a plain navigation rather than
        // blocking the user -- they still arrive at the page, just without
        // the session bridge.
        Embed.call(iframe, 'Users.bridge.mint', {}, function (err, token) {
            if (err || typeof token !== 'string' || !token) {
                window.location.assign(href);
                return;
            }
            u.searchParams.set('Q.Users.intent', token);
            window.location.assign(u.href);
        });
    };

    // -----------------------------------------------------------------------
    // Boot
    // -----------------------------------------------------------------------
    Q.Users.Embed = Embed;
    function bindClicks() {
        if (document.body) document.body.addEventListener('click', Embed._onClick, false);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bindClicks);
    else bindClicks();
    Q.log('Q.Users.Embed initialized, Qbix origin: ' + Embed.origin);
})(window, document);
