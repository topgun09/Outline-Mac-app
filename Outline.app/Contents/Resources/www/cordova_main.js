(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __extends = undefined && undefined.__extends || function () {
    var extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function (d, b) {
        d.__proto__ = b;
    } || function (d, b) {
        for (var p in b) {
            if (b.hasOwnProperty(p)) d[p] = b[p];
        }
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() {
            this.constructor = d;
        }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
}();
(function iife() {
    var platformExportObj = function detectPlatformExportObj() {
        if (typeof module !== 'undefined' && module.exports) {
            return module.exports; // node
        } else if (typeof window !== 'undefined') {
            return window; // browser
        }
        throw new Error('Could not detect platform global object (no window or module.exports)');
    }();
    /* tslint:disable */
    var isBrowser = typeof window !== 'undefined';
    var b64Encode = isBrowser ? btoa : require('base-64').encode;
    var b64Decode = isBrowser ? atob : require('base-64').decode;
    var URL = isBrowser ? window.URL : require('url').URL;
    var punycode = isBrowser ? window.punycode : require('punycode');
    if (!punycode) {
        throw new Error("Could not find punycode. Did you forget to add e.g.\n  <script src=\"bower_components/punycode/punycode.min.js\"></script>?");
    }
    /* tslint:enable */
    // Custom error base class
    var ShadowsocksConfigError = /** @class */function (_super) {
        __extends(ShadowsocksConfigError, _super);
        function ShadowsocksConfigError(message) {
            var _newTarget = this.constructor;
            var _this = _super.call(this, message) || this;
            Object.setPrototypeOf(_this, _newTarget.prototype); // restore prototype chain
            _this.name = _newTarget.name;
            return _this;
        }
        return ShadowsocksConfigError;
    }(Error);
    platformExportObj.ShadowsocksConfigError = ShadowsocksConfigError;
    var InvalidConfigField = /** @class */function (_super) {
        __extends(InvalidConfigField, _super);
        function InvalidConfigField() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return InvalidConfigField;
    }(ShadowsocksConfigError);
    platformExportObj.InvalidConfigField = InvalidConfigField;
    var InvalidUri = /** @class */function (_super) {
        __extends(InvalidUri, _super);
        function InvalidUri() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return InvalidUri;
    }(ShadowsocksConfigError);
    platformExportObj.InvalidUri = InvalidUri;
    // Self-validating/normalizing config data types implement this ValidatedConfigField interface.
    // Constructors take some data, validate, normalize, and store if valid, or throw otherwise.
    var ValidatedConfigField = /** @class */function () {
        function ValidatedConfigField() {}
        return ValidatedConfigField;
    }();
    platformExportObj.ValidatedConfigField = ValidatedConfigField;
    function throwErrorForInvalidField(name, value, reason) {
        throw new InvalidConfigField("Invalid " + name + ": " + value + " " + (reason || ''));
    }
    var Host = /** @class */function (_super) {
        __extends(Host, _super);
        function Host(host) {
            var _this = _super.call(this) || this;
            if (!host) {
                throwErrorForInvalidField('host', host);
            }
            if (host instanceof Host) {
                host = host.data;
            }
            host = punycode.toASCII(host);
            _this.isIPv4 = Host.IPV4_PATTERN.test(host);
            _this.isIPv6 = _this.isIPv4 ? false : Host.IPV6_PATTERN.test(host);
            _this.isHostname = _this.isIPv4 || _this.isIPv6 ? false : Host.HOSTNAME_PATTERN.test(host);
            if (!(_this.isIPv4 || _this.isIPv6 || _this.isHostname)) {
                throwErrorForInvalidField('host', host);
            }
            _this.data = host;
            return _this;
        }
        Host.IPV4_PATTERN = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        Host.IPV6_PATTERN = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
        Host.HOSTNAME_PATTERN = /^[A-z0-9]+[A-z0-9_.-]*$/;
        return Host;
    }(ValidatedConfigField);
    platformExportObj.Host = Host;
    var Port = /** @class */function (_super) {
        __extends(Port, _super);
        function Port(port) {
            var _this = _super.call(this) || this;
            if (port instanceof Port) {
                port = port.data;
            }
            if (typeof port === 'number') {
                // Stringify in case negative or floating point -> the regex test below will catch.
                port = port.toString();
            }
            if (!Port.PATTERN.test(port)) {
                throwErrorForInvalidField('port', port);
            }
            // Could exceed the maximum port number, so convert to Number to check. Could also have leading
            // zeros. Converting to Number drops those, so we get normalization for free. :)
            port = Number(port);
            if (port > 65535) {
                throwErrorForInvalidField('port', port);
            }
            _this.data = port;
            return _this;
        }
        Port.PATTERN = /^[0-9]{1,5}$/;
        return Port;
    }(ValidatedConfigField);
    platformExportObj.Port = Port;
    // A method value must exactly match an element in the set of known ciphers.
    // ref: https://github.com/shadowsocks/shadowsocks-libev/blob/10a2d3e3/completions/bash/ss-redir#L5
    platformExportObj.METHODS = new Set(['rc4-md5', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb', 'bf-cfb', 'chacha20-ietf-poly1305', 'salsa20', 'chacha20', 'chacha20-ietf', 'xchacha20-ietf-poly1305']);
    var Method = /** @class */function (_super) {
        __extends(Method, _super);
        function Method(method) {
            var _this = _super.call(this) || this;
            if (method instanceof Method) {
                method = method.data;
            }
            if (!platformExportObj.METHODS.has(method)) {
                throwErrorForInvalidField('method', method);
            }
            _this.data = method;
            return _this;
        }
        return Method;
    }(ValidatedConfigField);
    platformExportObj.Method = Method;
    var Password = /** @class */function (_super) {
        __extends(Password, _super);
        function Password(password) {
            var _this = _super.call(this) || this;
            _this.data = password instanceof Password ? password.data : password;
            return _this;
        }
        return Password;
    }(ValidatedConfigField);
    platformExportObj.Password = Password;
    var Tag = /** @class */function (_super) {
        __extends(Tag, _super);
        function Tag(tag) {
            if (tag === void 0) {
                tag = '';
            }
            var _this = _super.call(this) || this;
            _this.data = tag instanceof Tag ? tag.data : tag;
            return _this;
        }
        return Tag;
    }(ValidatedConfigField);
    platformExportObj.Tag = Tag;
    // tslint:disable-next-line:no-any
    function makeConfig(input) {
        // Use "!" for the required fields to tell tsc that we handle undefined in the
        // ValidatedConfigFields we call; tsc can't figure that out otherwise.
        var config = {
            host: new Host(input.host),
            port: new Port(input.port),
            method: new Method(input.method),
            password: new Password(input.password),
            tag: new Tag(input.tag),
            extra: {}
        };
        // Put any remaining fields in `input` into `config.extra`.
        for (var _i = 0, _a = Object.keys(input); _i < _a.length; _i++) {
            var key = _a[_i];
            if (!/^(host|port|method|password|tag)$/.test(key)) {
                config.extra[key] = input[key] && input[key].toString();
            }
        }
        return config;
    }
    platformExportObj.makeConfig = makeConfig;
    platformExportObj.SHADOWSOCKS_URI = {
        PROTOCOL: 'ss:',
        getUriFormattedHost: function getUriFormattedHost(host) {
            return host.isIPv6 ? "[" + host.data + "]" : host.data;
        },
        getHash: function getHash(tag) {
            return tag.data ? "#" + encodeURIComponent(tag.data) : '';
        },
        validateProtocol: function validateProtocol(uri) {
            if (!uri.startsWith(platformExportObj.SHADOWSOCKS_URI.PROTOCOL)) {
                throw new InvalidUri("URI must start with \"" + platformExportObj.SHADOWSOCKS_URI.PROTOCOL + "\"");
            }
        },
        parse: function parse(uri) {
            var error;
            for (var _i = 0, _a = [platformExportObj.SIP002_URI, platformExportObj.LEGACY_BASE64_URI]; _i < _a.length; _i++) {
                var uriType = _a[_i];
                try {
                    return uriType.parse(uri);
                } catch (e) {
                    error = e;
                }
            }
            if (!(error instanceof InvalidUri)) {
                var originalErrorName = error.name || '(Unnamed Error)';
                var originalErrorMessage = error.message || '(no error message provided)';
                var originalErrorString = originalErrorName + ": " + originalErrorMessage;
                var newErrorMessage = "Invalid input: " + originalErrorString;
                error = new InvalidUri(newErrorMessage);
            }
            throw error;
        }
    };
    // Ref: https://shadowsocks.org/en/config/quick-guide.html
    platformExportObj.LEGACY_BASE64_URI = {
        parse: function parse(uri) {
            platformExportObj.SHADOWSOCKS_URI.validateProtocol(uri);
            var hashIndex = uri.indexOf('#');
            var hasTag = hashIndex !== -1;
            var b64EndIndex = hasTag ? hashIndex : uri.length;
            var tagStartIndex = hasTag ? hashIndex + 1 : uri.length;
            var tag = new Tag(decodeURIComponent(uri.substring(tagStartIndex)));
            var b64EncodedData = uri.substring('ss://'.length, b64EndIndex);
            var b64DecodedData = b64Decode(b64EncodedData);
            var atSignIndex = b64DecodedData.lastIndexOf('@');
            if (atSignIndex === -1) {
                throw new InvalidUri("Missing \"@\"");
            }
            var methodAndPassword = b64DecodedData.substring(0, atSignIndex);
            var methodEndIndex = methodAndPassword.indexOf(':');
            if (methodEndIndex === -1) {
                throw new InvalidUri("Missing password");
            }
            var methodString = methodAndPassword.substring(0, methodEndIndex);
            var method = new Method(methodString);
            var passwordStartIndex = methodEndIndex + 1;
            var passwordString = methodAndPassword.substring(passwordStartIndex);
            var password = new Password(passwordString);
            var hostStartIndex = atSignIndex + 1;
            var hostAndPort = b64DecodedData.substring(hostStartIndex);
            var hostEndIndex = hostAndPort.lastIndexOf(':');
            if (hostEndIndex === -1) {
                throw new InvalidUri("Missing port");
            }
            var uriFormattedHost = hostAndPort.substring(0, hostEndIndex);
            var host;
            try {
                host = new Host(uriFormattedHost);
            } catch (_) {
                // Could be IPv6 host formatted with surrounding brackets, so try stripping first and last
                // characters. If this throws, give up and let the exception propagate.
                host = new Host(uriFormattedHost.substring(1, uriFormattedHost.length - 1));
            }
            var portStartIndex = hostEndIndex + 1;
            var portString = hostAndPort.substring(portStartIndex);
            var port = new Port(portString);
            var extra = {}; // empty because LegacyBase64Uri can't hold extra
            return { method: method, password: password, host: host, port: port, tag: tag, extra: extra };
        },
        stringify: function stringify(config) {
            var host = config.host,
                port = config.port,
                method = config.method,
                password = config.password,
                tag = config.tag;
            var hash = platformExportObj.SHADOWSOCKS_URI.getHash(tag);
            var b64EncodedData = b64Encode(method.data + ":" + password.data + "@" + host.data + ":" + port.data);
            var dataLength = b64EncodedData.length;
            var paddingLength = 0;
            for (; b64EncodedData[dataLength - 1 - paddingLength] === '='; paddingLength++) {}
            b64EncodedData = paddingLength === 0 ? b64EncodedData : b64EncodedData.substring(0, dataLength - paddingLength);
            return "ss://" + b64EncodedData + hash;
        }
    };
    // Ref: https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html
    platformExportObj.SIP002_URI = {
        parse: function parse(uri) {
            platformExportObj.SHADOWSOCKS_URI.validateProtocol(uri);
            // Can use built-in URL parser for expedience. Just have to replace "ss" with "http" to ensure
            // correct results, otherwise browsers like Safari fail to parse it.
            var inputForUrlParser = "http" + uri.substring(2);
            // The built-in URL parser throws as desired when given URIs with invalid syntax.
            var urlParserResult = new URL(inputForUrlParser);
            var uriFormattedHost = urlParserResult.hostname;
            // URI-formatted IPv6 hostnames have surrounding brackets.
            var last = uriFormattedHost.length - 1;
            var brackets = uriFormattedHost[0] === '[' && uriFormattedHost[last] === ']';
            var hostString = brackets ? uriFormattedHost.substring(1, last) : uriFormattedHost;
            var host = new Host(hostString);
            var parsedPort = urlParserResult.port;
            if (!parsedPort && uri.match(/:80($|\/)/g)) {
                // The default URL parser fails to recognize the default port (80) when the URI being parsed
                // is HTTP. Check if the port is present at the end of the string or before the parameters.
                parsedPort = 80;
            }
            var port = new Port(parsedPort);
            var tag = new Tag(decodeURIComponent(urlParserResult.hash.substring(1)));
            var b64EncodedUserInfo = urlParserResult.username.replace(/%3D/g, '=');
            // base64.decode throws as desired when given invalid base64 input.
            var b64DecodedUserInfo = b64Decode(b64EncodedUserInfo);
            var colonIdx = b64DecodedUserInfo.indexOf(':');
            if (colonIdx === -1) {
                throw new InvalidUri("Missing password");
            }
            var methodString = b64DecodedUserInfo.substring(0, colonIdx);
            var method = new Method(methodString);
            var passwordString = b64DecodedUserInfo.substring(colonIdx + 1);
            var password = new Password(passwordString);
            var queryParams = urlParserResult.search.substring(1).split('&');
            var extra = {};
            for (var _i = 0, queryParams_1 = queryParams; _i < queryParams_1.length; _i++) {
                var pair = queryParams_1[_i];
                var _a = pair.split('=', 2),
                    key = _a[0],
                    value = _a[1];
                if (!key) continue;
                extra[key] = decodeURIComponent(value || '');
            }
            return { method: method, password: password, host: host, port: port, tag: tag, extra: extra };
        },
        stringify: function stringify(config) {
            var host = config.host,
                port = config.port,
                method = config.method,
                password = config.password,
                tag = config.tag,
                extra = config.extra;
            var userInfo = b64Encode(method.data + ":" + password.data);
            var uriHost = platformExportObj.SHADOWSOCKS_URI.getUriFormattedHost(host);
            var hash = platformExportObj.SHADOWSOCKS_URI.getHash(tag);
            var queryString = '';
            for (var key in extra) {
                if (!key) continue;
                queryString += (queryString ? '&' : '?') + (key + "=" + encodeURIComponent(extra[key]));
            }
            return "ss://" + userInfo + "@" + uriHost + ":" + port.data + "/" + queryString + hash;
        }
    };
})();

},{"base-64":2,"punycode":3,"url":14}],2:[function(require,module,exports){
(function (global){
'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

/*! http://mths.be/base64 v0.1.0 by @mathias | MIT license */
;(function (root) {

	// Detect free variables `exports`.
	var freeExports = (typeof exports === 'undefined' ? 'undefined' : _typeof(exports)) == 'object' && exports;

	// Detect free variable `module`.
	var freeModule = (typeof module === 'undefined' ? 'undefined' : _typeof(module)) == 'object' && module && module.exports == freeExports && module;

	// Detect free variable `global`, from Node.js or Browserified code, and use
	// it as `root`.
	var freeGlobal = (typeof global === 'undefined' ? 'undefined' : _typeof(global)) == 'object' && global;
	if (freeGlobal.global === freeGlobal || freeGlobal.window === freeGlobal) {
		root = freeGlobal;
	}

	/*--------------------------------------------------------------------------*/

	var InvalidCharacterError = function InvalidCharacterError(message) {
		this.message = message;
	};
	InvalidCharacterError.prototype = new Error();
	InvalidCharacterError.prototype.name = 'InvalidCharacterError';

	var error = function error(message) {
		// Note: the error messages used throughout this file match those used by
		// the native `atob`/`btoa` implementation in Chromium.
		throw new InvalidCharacterError(message);
	};

	var TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	// http://whatwg.org/html/common-microsyntaxes.html#space-character
	var REGEX_SPACE_CHARACTERS = /[\t\n\f\r ]/g;

	// `decode` is designed to be fully compatible with `atob` as described in the
	// HTML Standard. http://whatwg.org/html/webappapis.html#dom-windowbase64-atob
	// The optimized base64-decoding algorithm used is based on @atk’s excellent
	// implementation. https://gist.github.com/atk/1020396
	var decode = function decode(input) {
		input = String(input).replace(REGEX_SPACE_CHARACTERS, '');
		var length = input.length;
		if (length % 4 == 0) {
			input = input.replace(/==?$/, '');
			length = input.length;
		}
		if (length % 4 == 1 ||
		// http://whatwg.org/C#alphanumeric-ascii-characters
		/[^+a-zA-Z0-9/]/.test(input)) {
			error('Invalid character: the string to be decoded is not correctly encoded.');
		}
		var bitCounter = 0;
		var bitStorage;
		var buffer;
		var output = '';
		var position = -1;
		while (++position < length) {
			buffer = TABLE.indexOf(input.charAt(position));
			bitStorage = bitCounter % 4 ? bitStorage * 64 + buffer : buffer;
			// Unless this is the first of a group of 4 characters…
			if (bitCounter++ % 4) {
				// …convert the first 8 bits to a single ASCII character.
				output += String.fromCharCode(0xFF & bitStorage >> (-2 * bitCounter & 6));
			}
		}
		return output;
	};

	// `encode` is designed to be fully compatible with `btoa` as described in the
	// HTML Standard: http://whatwg.org/html/webappapis.html#dom-windowbase64-btoa
	var encode = function encode(input) {
		input = String(input);
		if (/[^\0-\xFF]/.test(input)) {
			// Note: no need to special-case astral symbols here, as surrogates are
			// matched, and the input is supposed to only contain ASCII anyway.
			error('The string to be encoded contains characters outside of the ' + 'Latin1 range.');
		}
		var padding = input.length % 3;
		var output = '';
		var position = -1;
		var a;
		var b;
		var c;
		var d;
		var buffer;
		// Make sure any padding is handled outside of the loop.
		var length = input.length - padding;

		while (++position < length) {
			// Read three bytes, i.e. 24 bits.
			a = input.charCodeAt(position) << 16;
			b = input.charCodeAt(++position) << 8;
			c = input.charCodeAt(++position);
			buffer = a + b + c;
			// Turn the 24 bits into four chunks of 6 bits each, and append the
			// matching character for each of them to the output.
			output += TABLE.charAt(buffer >> 18 & 0x3F) + TABLE.charAt(buffer >> 12 & 0x3F) + TABLE.charAt(buffer >> 6 & 0x3F) + TABLE.charAt(buffer & 0x3F);
		}

		if (padding == 2) {
			a = input.charCodeAt(position) << 8;
			b = input.charCodeAt(++position);
			buffer = a + b;
			output += TABLE.charAt(buffer >> 10) + TABLE.charAt(buffer >> 4 & 0x3F) + TABLE.charAt(buffer << 2 & 0x3F) + '=';
		} else if (padding == 1) {
			buffer = input.charCodeAt(position);
			output += TABLE.charAt(buffer >> 2) + TABLE.charAt(buffer << 4 & 0x3F) + '==';
		}

		return output;
	};

	var base64 = {
		'encode': encode,
		'decode': decode,
		'version': '0.1.0'
	};

	// Some AMD build optimizers, like r.js, check for specific condition patterns
	// like the following:
	if (typeof define == 'function' && _typeof(define.amd) == 'object' && define.amd) {
		define(function () {
			return base64;
		});
	} else if (freeExports && !freeExports.nodeType) {
		if (freeModule) {
			// in Node.js or RingoJS v0.8.0+
			freeModule.exports = base64;
		} else {
			// in Narwhal or RingoJS v0.7.0-
			for (var key in base64) {
				base64.hasOwnProperty(key) && (freeExports[key] = base64[key]);
			}
		}
	} else {
		// in Rhino or a web browser
		root.base64 = base64;
	}
})(undefined);

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],3:[function(require,module,exports){
(function (global){
'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

/*! https://mths.be/punycode v1.4.1 by @mathias */
;(function (root) {

	/** Detect free variables */
	var freeExports = (typeof exports === 'undefined' ? 'undefined' : _typeof(exports)) == 'object' && exports && !exports.nodeType && exports;
	var freeModule = (typeof module === 'undefined' ? 'undefined' : _typeof(module)) == 'object' && module && !module.nodeType && module;
	var freeGlobal = (typeof global === 'undefined' ? 'undefined' : _typeof(global)) == 'object' && global;
	if (freeGlobal.global === freeGlobal || freeGlobal.window === freeGlobal || freeGlobal.self === freeGlobal) {
		root = freeGlobal;
	}

	/**
  * The `punycode` object.
  * @name punycode
  * @type Object
  */
	var punycode,


	/** Highest positive signed 32-bit float value */
	maxInt = 2147483647,
	    // aka. 0x7FFFFFFF or 2^31-1

	/** Bootstring parameters */
	base = 36,
	    tMin = 1,
	    tMax = 26,
	    skew = 38,
	    damp = 700,
	    initialBias = 72,
	    initialN = 128,
	    // 0x80
	delimiter = '-',
	    // '\x2D'

	/** Regular expressions */
	regexPunycode = /^xn--/,
	    regexNonASCII = /[^\x20-\x7E]/,
	    // unprintable ASCII chars + non-ASCII chars
	regexSeparators = /[\x2E\u3002\uFF0E\uFF61]/g,
	    // RFC 3490 separators

	/** Error messages */
	errors = {
		'overflow': 'Overflow: input needs wider integers to process',
		'not-basic': 'Illegal input >= 0x80 (not a basic code point)',
		'invalid-input': 'Invalid input'
	},


	/** Convenience shortcuts */
	baseMinusTMin = base - tMin,
	    floor = Math.floor,
	    stringFromCharCode = String.fromCharCode,


	/** Temporary variable */
	key;

	/*--------------------------------------------------------------------------*/

	/**
  * A generic error utility function.
  * @private
  * @param {String} type The error type.
  * @returns {Error} Throws a `RangeError` with the applicable error message.
  */
	function error(type) {
		throw new RangeError(errors[type]);
	}

	/**
  * A generic `Array#map` utility function.
  * @private
  * @param {Array} array The array to iterate over.
  * @param {Function} callback The function that gets called for every array
  * item.
  * @returns {Array} A new array of values returned by the callback function.
  */
	function map(array, fn) {
		var length = array.length;
		var result = [];
		while (length--) {
			result[length] = fn(array[length]);
		}
		return result;
	}

	/**
  * A simple `Array#map`-like wrapper to work with domain name strings or email
  * addresses.
  * @private
  * @param {String} domain The domain name or email address.
  * @param {Function} callback The function that gets called for every
  * character.
  * @returns {Array} A new string of characters returned by the callback
  * function.
  */
	function mapDomain(string, fn) {
		var parts = string.split('@');
		var result = '';
		if (parts.length > 1) {
			// In email addresses, only the domain name should be punycoded. Leave
			// the local part (i.e. everything up to `@`) intact.
			result = parts[0] + '@';
			string = parts[1];
		}
		// Avoid `split(regex)` for IE8 compatibility. See #17.
		string = string.replace(regexSeparators, '\x2E');
		var labels = string.split('.');
		var encoded = map(labels, fn).join('.');
		return result + encoded;
	}

	/**
  * Creates an array containing the numeric code points of each Unicode
  * character in the string. While JavaScript uses UCS-2 internally,
  * this function will convert a pair of surrogate halves (each of which
  * UCS-2 exposes as separate characters) into a single code point,
  * matching UTF-16.
  * @see `punycode.ucs2.encode`
  * @see <https://mathiasbynens.be/notes/javascript-encoding>
  * @memberOf punycode.ucs2
  * @name decode
  * @param {String} string The Unicode input string (UCS-2).
  * @returns {Array} The new array of code points.
  */
	function ucs2decode(string) {
		var output = [],
		    counter = 0,
		    length = string.length,
		    value,
		    extra;
		while (counter < length) {
			value = string.charCodeAt(counter++);
			if (value >= 0xD800 && value <= 0xDBFF && counter < length) {
				// high surrogate, and there is a next character
				extra = string.charCodeAt(counter++);
				if ((extra & 0xFC00) == 0xDC00) {
					// low surrogate
					output.push(((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000);
				} else {
					// unmatched surrogate; only append this code unit, in case the next
					// code unit is the high surrogate of a surrogate pair
					output.push(value);
					counter--;
				}
			} else {
				output.push(value);
			}
		}
		return output;
	}

	/**
  * Creates a string based on an array of numeric code points.
  * @see `punycode.ucs2.decode`
  * @memberOf punycode.ucs2
  * @name encode
  * @param {Array} codePoints The array of numeric code points.
  * @returns {String} The new Unicode string (UCS-2).
  */
	function ucs2encode(array) {
		return map(array, function (value) {
			var output = '';
			if (value > 0xFFFF) {
				value -= 0x10000;
				output += stringFromCharCode(value >>> 10 & 0x3FF | 0xD800);
				value = 0xDC00 | value & 0x3FF;
			}
			output += stringFromCharCode(value);
			return output;
		}).join('');
	}

	/**
  * Converts a basic code point into a digit/integer.
  * @see `digitToBasic()`
  * @private
  * @param {Number} codePoint The basic numeric code point value.
  * @returns {Number} The numeric value of a basic code point (for use in
  * representing integers) in the range `0` to `base - 1`, or `base` if
  * the code point does not represent a value.
  */
	function basicToDigit(codePoint) {
		if (codePoint - 48 < 10) {
			return codePoint - 22;
		}
		if (codePoint - 65 < 26) {
			return codePoint - 65;
		}
		if (codePoint - 97 < 26) {
			return codePoint - 97;
		}
		return base;
	}

	/**
  * Converts a digit/integer into a basic code point.
  * @see `basicToDigit()`
  * @private
  * @param {Number} digit The numeric value of a basic code point.
  * @returns {Number} The basic code point whose value (when used for
  * representing integers) is `digit`, which needs to be in the range
  * `0` to `base - 1`. If `flag` is non-zero, the uppercase form is
  * used; else, the lowercase form is used. The behavior is undefined
  * if `flag` is non-zero and `digit` has no uppercase form.
  */
	function digitToBasic(digit, flag) {
		//  0..25 map to ASCII a..z or A..Z
		// 26..35 map to ASCII 0..9
		return digit + 22 + 75 * (digit < 26) - ((flag != 0) << 5);
	}

	/**
  * Bias adaptation function as per section 3.4 of RFC 3492.
  * https://tools.ietf.org/html/rfc3492#section-3.4
  * @private
  */
	function adapt(delta, numPoints, firstTime) {
		var k = 0;
		delta = firstTime ? floor(delta / damp) : delta >> 1;
		delta += floor(delta / numPoints);
		for (; /* no initialization */delta > baseMinusTMin * tMax >> 1; k += base) {
			delta = floor(delta / baseMinusTMin);
		}
		return floor(k + (baseMinusTMin + 1) * delta / (delta + skew));
	}

	/**
  * Converts a Punycode string of ASCII-only symbols to a string of Unicode
  * symbols.
  * @memberOf punycode
  * @param {String} input The Punycode string of ASCII-only symbols.
  * @returns {String} The resulting string of Unicode symbols.
  */
	function decode(input) {
		// Don't use UCS-2
		var output = [],
		    inputLength = input.length,
		    out,
		    i = 0,
		    n = initialN,
		    bias = initialBias,
		    basic,
		    j,
		    index,
		    oldi,
		    w,
		    k,
		    digit,
		    t,

		/** Cached calculation results */
		baseMinusT;

		// Handle the basic code points: let `basic` be the number of input code
		// points before the last delimiter, or `0` if there is none, then copy
		// the first basic code points to the output.

		basic = input.lastIndexOf(delimiter);
		if (basic < 0) {
			basic = 0;
		}

		for (j = 0; j < basic; ++j) {
			// if it's not a basic code point
			if (input.charCodeAt(j) >= 0x80) {
				error('not-basic');
			}
			output.push(input.charCodeAt(j));
		}

		// Main decoding loop: start just after the last delimiter if any basic code
		// points were copied; start at the beginning otherwise.

		for (index = basic > 0 ? basic + 1 : 0; index < inputLength;) /* no final expression */{

			// `index` is the index of the next character to be consumed.
			// Decode a generalized variable-length integer into `delta`,
			// which gets added to `i`. The overflow checking is easier
			// if we increase `i` as we go, then subtract off its starting
			// value at the end to obtain `delta`.
			for (oldi = i, w = 1, k = base;; /* no condition */k += base) {

				if (index >= inputLength) {
					error('invalid-input');
				}

				digit = basicToDigit(input.charCodeAt(index++));

				if (digit >= base || digit > floor((maxInt - i) / w)) {
					error('overflow');
				}

				i += digit * w;
				t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;

				if (digit < t) {
					break;
				}

				baseMinusT = base - t;
				if (w > floor(maxInt / baseMinusT)) {
					error('overflow');
				}

				w *= baseMinusT;
			}

			out = output.length + 1;
			bias = adapt(i - oldi, out, oldi == 0);

			// `i` was supposed to wrap around from `out` to `0`,
			// incrementing `n` each time, so we'll fix that now:
			if (floor(i / out) > maxInt - n) {
				error('overflow');
			}

			n += floor(i / out);
			i %= out;

			// Insert `n` at position `i` of the output
			output.splice(i++, 0, n);
		}

		return ucs2encode(output);
	}

	/**
  * Converts a string of Unicode symbols (e.g. a domain name label) to a
  * Punycode string of ASCII-only symbols.
  * @memberOf punycode
  * @param {String} input The string of Unicode symbols.
  * @returns {String} The resulting Punycode string of ASCII-only symbols.
  */
	function encode(input) {
		var n,
		    delta,
		    handledCPCount,
		    basicLength,
		    bias,
		    j,
		    m,
		    q,
		    k,
		    t,
		    currentValue,
		    output = [],

		/** `inputLength` will hold the number of code points in `input`. */
		inputLength,

		/** Cached calculation results */
		handledCPCountPlusOne,
		    baseMinusT,
		    qMinusT;

		// Convert the input in UCS-2 to Unicode
		input = ucs2decode(input);

		// Cache the length
		inputLength = input.length;

		// Initialize the state
		n = initialN;
		delta = 0;
		bias = initialBias;

		// Handle the basic code points
		for (j = 0; j < inputLength; ++j) {
			currentValue = input[j];
			if (currentValue < 0x80) {
				output.push(stringFromCharCode(currentValue));
			}
		}

		handledCPCount = basicLength = output.length;

		// `handledCPCount` is the number of code points that have been handled;
		// `basicLength` is the number of basic code points.

		// Finish the basic string - if it is not empty - with a delimiter
		if (basicLength) {
			output.push(delimiter);
		}

		// Main encoding loop:
		while (handledCPCount < inputLength) {

			// All non-basic code points < n have been handled already. Find the next
			// larger one:
			for (m = maxInt, j = 0; j < inputLength; ++j) {
				currentValue = input[j];
				if (currentValue >= n && currentValue < m) {
					m = currentValue;
				}
			}

			// Increase `delta` enough to advance the decoder's <n,i> state to <m,0>,
			// but guard against overflow
			handledCPCountPlusOne = handledCPCount + 1;
			if (m - n > floor((maxInt - delta) / handledCPCountPlusOne)) {
				error('overflow');
			}

			delta += (m - n) * handledCPCountPlusOne;
			n = m;

			for (j = 0; j < inputLength; ++j) {
				currentValue = input[j];

				if (currentValue < n && ++delta > maxInt) {
					error('overflow');
				}

				if (currentValue == n) {
					// Represent delta as a generalized variable-length integer
					for (q = delta, k = base;; /* no condition */k += base) {
						t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
						if (q < t) {
							break;
						}
						qMinusT = q - t;
						baseMinusT = base - t;
						output.push(stringFromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0)));
						q = floor(qMinusT / baseMinusT);
					}

					output.push(stringFromCharCode(digitToBasic(q, 0)));
					bias = adapt(delta, handledCPCountPlusOne, handledCPCount == basicLength);
					delta = 0;
					++handledCPCount;
				}
			}

			++delta;
			++n;
		}
		return output.join('');
	}

	/**
  * Converts a Punycode string representing a domain name or an email address
  * to Unicode. Only the Punycoded parts of the input will be converted, i.e.
  * it doesn't matter if you call it on a string that has already been
  * converted to Unicode.
  * @memberOf punycode
  * @param {String} input The Punycoded domain name or email address to
  * convert to Unicode.
  * @returns {String} The Unicode representation of the given Punycode
  * string.
  */
	function toUnicode(input) {
		return mapDomain(input, function (string) {
			return regexPunycode.test(string) ? decode(string.slice(4).toLowerCase()) : string;
		});
	}

	/**
  * Converts a Unicode string representing a domain name or an email address to
  * Punycode. Only the non-ASCII parts of the domain name will be converted,
  * i.e. it doesn't matter if you call it with a domain that's already in
  * ASCII.
  * @memberOf punycode
  * @param {String} input The domain name or email address to convert, as a
  * Unicode string.
  * @returns {String} The Punycode representation of the given domain name or
  * email address.
  */
	function toASCII(input) {
		return mapDomain(input, function (string) {
			return regexNonASCII.test(string) ? 'xn--' + encode(string) : string;
		});
	}

	/*--------------------------------------------------------------------------*/

	/** Define the public API */
	punycode = {
		/**
   * A string representing the current Punycode.js version number.
   * @memberOf punycode
   * @type String
   */
		'version': '1.4.1',
		/**
   * An object of methods to convert from JavaScript's internal character
   * representation (UCS-2) to Unicode code points, and back.
   * @see <https://mathiasbynens.be/notes/javascript-encoding>
   * @memberOf punycode
   * @type Object
   */
		'ucs2': {
			'decode': ucs2decode,
			'encode': ucs2encode
		},
		'decode': decode,
		'encode': encode,
		'toASCII': toASCII,
		'toUnicode': toUnicode
	};

	/** Expose `punycode` */
	// Some AMD build optimizers, like r.js, check for specific condition patterns
	// like the following:
	if (typeof define == 'function' && _typeof(define.amd) == 'object' && define.amd) {
		define('punycode', function () {
			return punycode;
		});
	} else if (freeExports && freeModule) {
		if (module.exports == freeExports) {
			// in Node.js, io.js, or RingoJS v0.8.0+
			freeModule.exports = punycode;
		} else {
			// in Narwhal or RingoJS v0.7.0-
			for (key in punycode) {
				punycode.hasOwnProperty(key) && (freeExports[key] = punycode[key]);
			}
		}
	} else {
		// in Rhino or a web browser
		root.punycode = punycode;
	}
})(undefined);

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],4:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

// If obj.hasOwnProperty has been overridden, then calling
// obj.hasOwnProperty(prop) will break.
// See: https://github.com/joyent/node/issues/1707

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

module.exports = function (qs, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var obj = {};

  if (typeof qs !== 'string' || qs.length === 0) {
    return obj;
  }

  var regexp = /\+/g;
  qs = qs.split(sep);

  var maxKeys = 1000;
  if (options && typeof options.maxKeys === 'number') {
    maxKeys = options.maxKeys;
  }

  var len = qs.length;
  // maxKeys <= 0 means that we should not limit keys count
  if (maxKeys > 0 && len > maxKeys) {
    len = maxKeys;
  }

  for (var i = 0; i < len; ++i) {
    var x = qs[i].replace(regexp, '%20'),
        idx = x.indexOf(eq),
        kstr,
        vstr,
        k,
        v;

    if (idx >= 0) {
      kstr = x.substr(0, idx);
      vstr = x.substr(idx + 1);
    } else {
      kstr = x;
      vstr = '';
    }

    k = decodeURIComponent(kstr);
    v = decodeURIComponent(vstr);

    if (!hasOwnProperty(obj, k)) {
      obj[k] = v;
    } else if (isArray(obj[k])) {
      obj[k].push(v);
    } else {
      obj[k] = [obj[k], v];
    }
  }

  return obj;
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

},{}],5:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var stringifyPrimitive = function stringifyPrimitive(v) {
  switch (typeof v === 'undefined' ? 'undefined' : _typeof(v)) {
    case 'string':
      return v;

    case 'boolean':
      return v ? 'true' : 'false';

    case 'number':
      return isFinite(v) ? v : '';

    default:
      return '';
  }
};

module.exports = function (obj, sep, eq, name) {
  sep = sep || '&';
  eq = eq || '=';
  if (obj === null) {
    obj = undefined;
  }

  if ((typeof obj === 'undefined' ? 'undefined' : _typeof(obj)) === 'object') {
    return map(objectKeys(obj), function (k) {
      var ks = encodeURIComponent(stringifyPrimitive(k)) + eq;
      if (isArray(obj[k])) {
        return map(obj[k], function (v) {
          return ks + encodeURIComponent(stringifyPrimitive(v));
        }).join(sep);
      } else {
        return ks + encodeURIComponent(stringifyPrimitive(obj[k]));
      }
    }).join(sep);
  }

  if (!name) return '';
  return encodeURIComponent(stringifyPrimitive(name)) + eq + encodeURIComponent(stringifyPrimitive(obj));
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

function map(xs, f) {
  if (xs.map) return xs.map(f);
  var res = [];
  for (var i = 0; i < xs.length; i++) {
    res.push(f(xs[i], i));
  }
  return res;
}

var objectKeys = Object.keys || function (obj) {
  var res = [];
  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) res.push(key);
  }
  return res;
};

},{}],6:[function(require,module,exports){
'use strict';

exports.decode = exports.parse = require('./decode');
exports.encode = exports.stringify = require('./encode');

},{"./decode":4,"./encode":5}],7:[function(require,module,exports){
'use strict';

function RavenConfigError(message) {
  this.name = 'RavenConfigError';
  this.message = message;
}
RavenConfigError.prototype = new Error();
RavenConfigError.prototype.constructor = RavenConfigError;

module.exports = RavenConfigError;

},{}],8:[function(require,module,exports){
'use strict';

var wrapMethod = function wrapMethod(console, level, callback) {
  var originalConsoleLevel = console[level];
  var originalConsole = console;

  if (!(level in console)) {
    return;
  }

  var sentryLevel = level === 'warn' ? 'warning' : level;

  console[level] = function () {
    var args = [].slice.call(arguments);

    var msg = '' + args.join(' ');
    var data = { level: sentryLevel, logger: 'console', extra: { arguments: args } };

    if (level === 'assert') {
      if (args[0] === false) {
        // Default browsers message
        msg = 'Assertion failed: ' + (args.slice(1).join(' ') || 'console.assert');
        data.extra.arguments = args.slice(1);
        callback && callback(msg, data);
      }
    } else {
      callback && callback(msg, data);
    }

    // this fails for some browsers. :(
    if (originalConsoleLevel) {
      // IE9 doesn't allow calling apply on console functions directly
      // See: https://stackoverflow.com/questions/5472938/does-ie9-support-console-log-and-is-it-a-real-function#answer-5473193
      Function.prototype.apply.call(originalConsoleLevel, originalConsole, args);
    }
  };
};

module.exports = {
  wrapMethod: wrapMethod
};

},{}],9:[function(require,module,exports){
(function (global){
'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

/*global XDomainRequest:false */

var TraceKit = require('../vendor/TraceKit/tracekit');
var stringify = require('../vendor/json-stringify-safe/stringify');
var RavenConfigError = require('./configError');

var utils = require('./utils');
var isError = utils.isError;
var isObject = utils.isObject;
var isErrorEvent = utils.isErrorEvent;
var isUndefined = utils.isUndefined;
var isFunction = utils.isFunction;
var isString = utils.isString;
var isArray = utils.isArray;
var isEmptyObject = utils.isEmptyObject;
var each = utils.each;
var objectMerge = utils.objectMerge;
var truncate = utils.truncate;
var objectFrozen = utils.objectFrozen;
var hasKey = utils.hasKey;
var joinRegExp = utils.joinRegExp;
var urlencode = utils.urlencode;
var uuid4 = utils.uuid4;
var htmlTreeAsString = utils.htmlTreeAsString;
var isSameException = utils.isSameException;
var isSameStacktrace = utils.isSameStacktrace;
var parseUrl = utils.parseUrl;
var fill = utils.fill;

var wrapConsoleMethod = require('./console').wrapMethod;

var dsnKeys = 'source protocol user pass host port path'.split(' '),
    dsnPattern = /^(?:(\w+):)?\/\/(?:(\w+)(:\w+)?@)?([\w\.-]+)(?::(\d+))?(\/.*)/;

function now() {
  return +new Date();
}

// This is to be defensive in environments where window does not exist (see https://github.com/getsentry/raven-js/pull/785)
var _window = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};
var _document = _window.document;
var _navigator = _window.navigator;

function keepOriginalCallback(original, callback) {
  return isFunction(callback) ? function (data) {
    return callback(data, original);
  } : callback;
}

// First, check for JSON support
// If there is no JSON, we no-op the core features of Raven
// since JSON is required to encode the payload
function Raven() {
  this._hasJSON = !!((typeof JSON === 'undefined' ? 'undefined' : _typeof(JSON)) === 'object' && JSON.stringify);
  // Raven can run in contexts where there's no document (react-native)
  this._hasDocument = !isUndefined(_document);
  this._hasNavigator = !isUndefined(_navigator);
  this._lastCapturedException = null;
  this._lastData = null;
  this._lastEventId = null;
  this._globalServer = null;
  this._globalKey = null;
  this._globalProject = null;
  this._globalContext = {};
  this._globalOptions = {
    logger: 'javascript',
    ignoreErrors: [],
    ignoreUrls: [],
    whitelistUrls: [],
    includePaths: [],
    collectWindowErrors: true,
    maxMessageLength: 0,

    // By default, truncates URL values to 250 chars
    maxUrlLength: 250,
    stackTraceLimit: 50,
    autoBreadcrumbs: true,
    instrument: true,
    sampleRate: 1
  };
  this._ignoreOnError = 0;
  this._isRavenInstalled = false;
  this._originalErrorStackTraceLimit = Error.stackTraceLimit;
  // capture references to window.console *and* all its methods first
  // before the console plugin has a chance to monkey patch
  this._originalConsole = _window.console || {};
  this._originalConsoleMethods = {};
  this._plugins = [];
  this._startTime = now();
  this._wrappedBuiltIns = [];
  this._breadcrumbs = [];
  this._lastCapturedEvent = null;
  this._keypressTimeout;
  this._location = _window.location;
  this._lastHref = this._location && this._location.href;
  this._resetBackoff();

  // eslint-disable-next-line guard-for-in
  for (var method in this._originalConsole) {
    this._originalConsoleMethods[method] = this._originalConsole[method];
  }
}

/*
 * The core Raven singleton
 *
 * @this {Raven}
 */

Raven.prototype = {
  // Hardcode version string so that raven source can be loaded directly via
  // webpack (using a build step causes webpack #1617). Grunt verifies that
  // this value matches package.json during build.
  //   See: https://github.com/getsentry/raven-js/issues/465
  VERSION: '3.20.1',

  debug: false,

  TraceKit: TraceKit, // alias to TraceKit

  /*
     * Configure Raven with a DSN and extra options
     *
     * @param {string} dsn The public Sentry DSN
     * @param {object} options Set of global options [optional]
     * @return {Raven}
     */
  config: function config(dsn, options) {
    var self = this;

    if (self._globalServer) {
      this._logDebug('error', 'Error: Raven has already been configured');
      return self;
    }
    if (!dsn) return self;

    var globalOptions = self._globalOptions;

    // merge in options
    if (options) {
      each(options, function (key, value) {
        // tags and extra are special and need to be put into context
        if (key === 'tags' || key === 'extra' || key === 'user') {
          self._globalContext[key] = value;
        } else {
          globalOptions[key] = value;
        }
      });
    }

    self.setDSN(dsn);

    // "Script error." is hard coded into browsers for errors that it can't read.
    // this is the result of a script being pulled in from an external domain and CORS.
    globalOptions.ignoreErrors.push(/^Script error\.?$/);
    globalOptions.ignoreErrors.push(/^Javascript error: Script error\.? on line 0$/);

    // join regexp rules into one big rule
    globalOptions.ignoreErrors = joinRegExp(globalOptions.ignoreErrors);
    globalOptions.ignoreUrls = globalOptions.ignoreUrls.length ? joinRegExp(globalOptions.ignoreUrls) : false;
    globalOptions.whitelistUrls = globalOptions.whitelistUrls.length ? joinRegExp(globalOptions.whitelistUrls) : false;
    globalOptions.includePaths = joinRegExp(globalOptions.includePaths);
    globalOptions.maxBreadcrumbs = Math.max(0, Math.min(globalOptions.maxBreadcrumbs || 100, 100)); // default and hard limit is 100

    var autoBreadcrumbDefaults = {
      xhr: true,
      console: true,
      dom: true,
      location: true,
      sentry: true
    };

    var autoBreadcrumbs = globalOptions.autoBreadcrumbs;
    if ({}.toString.call(autoBreadcrumbs) === '[object Object]') {
      autoBreadcrumbs = objectMerge(autoBreadcrumbDefaults, autoBreadcrumbs);
    } else if (autoBreadcrumbs !== false) {
      autoBreadcrumbs = autoBreadcrumbDefaults;
    }
    globalOptions.autoBreadcrumbs = autoBreadcrumbs;

    var instrumentDefaults = {
      tryCatch: true
    };

    var instrument = globalOptions.instrument;
    if ({}.toString.call(instrument) === '[object Object]') {
      instrument = objectMerge(instrumentDefaults, instrument);
    } else if (instrument !== false) {
      instrument = instrumentDefaults;
    }
    globalOptions.instrument = instrument;

    TraceKit.collectWindowErrors = !!globalOptions.collectWindowErrors;

    // return for chaining
    return self;
  },

  /*
     * Installs a global window.onerror error handler
     * to capture and report uncaught exceptions.
     * At this point, install() is required to be called due
     * to the way TraceKit is set up.
     *
     * @return {Raven}
     */
  install: function install() {
    var self = this;
    if (self.isSetup() && !self._isRavenInstalled) {
      TraceKit.report.subscribe(function () {
        self._handleOnErrorStackInfo.apply(self, arguments);
      });

      self._patchFunctionToString();

      if (self._globalOptions.instrument && self._globalOptions.instrument.tryCatch) {
        self._instrumentTryCatch();
      }

      if (self._globalOptions.autoBreadcrumbs) self._instrumentBreadcrumbs();

      // Install all of the plugins
      self._drainPlugins();

      self._isRavenInstalled = true;
    }

    Error.stackTraceLimit = self._globalOptions.stackTraceLimit;
    return this;
  },

  /*
     * Set the DSN (can be called multiple time unlike config)
     *
     * @param {string} dsn The public Sentry DSN
     */
  setDSN: function setDSN(dsn) {
    var self = this,
        uri = self._parseDSN(dsn),
        lastSlash = uri.path.lastIndexOf('/'),
        path = uri.path.substr(1, lastSlash);

    self._dsn = dsn;
    self._globalKey = uri.user;
    self._globalSecret = uri.pass && uri.pass.substr(1);
    self._globalProject = uri.path.substr(lastSlash + 1);

    self._globalServer = self._getGlobalServer(uri);

    self._globalEndpoint = self._globalServer + '/' + path + 'api/' + self._globalProject + '/store/';

    // Reset backoff state since we may be pointing at a
    // new project/server
    this._resetBackoff();
  },

  /*
     * Wrap code within a context so Raven can capture errors
     * reliably across domains that is executed immediately.
     *
     * @param {object} options A specific set of options for this context [optional]
     * @param {function} func The callback to be immediately executed within the context
     * @param {array} args An array of arguments to be called with the callback [optional]
     */
  context: function context(options, func, args) {
    if (isFunction(options)) {
      args = func || [];
      func = options;
      options = undefined;
    }

    return this.wrap(options, func).apply(this, args);
  },

  /*
     * Wrap code within a context and returns back a new function to be executed
     *
     * @param {object} options A specific set of options for this context [optional]
     * @param {function} func The function to be wrapped in a new context
     * @param {function} func A function to call before the try/catch wrapper [optional, private]
     * @return {function} The newly wrapped functions with a context
     */
  wrap: function wrap(options, func, _before) {
    var self = this;
    // 1 argument has been passed, and it's not a function
    // so just return it
    if (isUndefined(func) && !isFunction(options)) {
      return options;
    }

    // options is optional
    if (isFunction(options)) {
      func = options;
      options = undefined;
    }

    // At this point, we've passed along 2 arguments, and the second one
    // is not a function either, so we'll just return the second argument.
    if (!isFunction(func)) {
      return func;
    }

    // We don't wanna wrap it twice!
    try {
      if (func.__raven__) {
        return func;
      }

      // If this has already been wrapped in the past, return that
      if (func.__raven_wrapper__) {
        return func.__raven_wrapper__;
      }
    } catch (e) {
      // Just accessing custom props in some Selenium environments
      // can cause a "Permission denied" exception (see raven-js#495).
      // Bail on wrapping and return the function as-is (defers to window.onerror).
      return func;
    }

    function wrapped() {
      var args = [],
          i = arguments.length,
          deep = !options || options && options.deep !== false;

      if (_before && isFunction(_before)) {
        _before.apply(this, arguments);
      }

      // Recursively wrap all of a function's arguments that are
      // functions themselves.
      while (i--) {
        args[i] = deep ? self.wrap(options, arguments[i]) : arguments[i];
      }try {
        // Attempt to invoke user-land function
        // NOTE: If you are a Sentry user, and you are seeing this stack frame, it
        //       means Raven caught an error invoking your application code. This is
        //       expected behavior and NOT indicative of a bug with Raven.js.
        return func.apply(this, args);
      } catch (e) {
        self._ignoreNextOnError();
        self.captureException(e, options);
        throw e;
      }
    }

    // copy over properties of the old function
    for (var property in func) {
      if (hasKey(func, property)) {
        wrapped[property] = func[property];
      }
    }
    wrapped.prototype = func.prototype;

    func.__raven_wrapper__ = wrapped;
    // Signal that this function has been wrapped/filled already
    // for both debugging and to prevent it to being wrapped/filled twice
    wrapped.__raven__ = true;
    wrapped.__orig__ = func;

    return wrapped;
  },

  /*
     * Uninstalls the global error handler.
     *
     * @return {Raven}
     */
  uninstall: function uninstall() {
    TraceKit.report.uninstall();

    this._unpatchFunctionToString();
    this._restoreBuiltIns();

    Error.stackTraceLimit = this._originalErrorStackTraceLimit;
    this._isRavenInstalled = false;

    return this;
  },

  /*
     * Manually capture an exception and send it over to Sentry
     *
     * @param {error} ex An exception to be logged
     * @param {object} options A specific set of options for this error [optional]
     * @return {Raven}
     */
  captureException: function captureException(ex, options) {
    // Cases for sending ex as a message, rather than an exception
    var isNotError = !isError(ex);
    var isNotErrorEvent = !isErrorEvent(ex);
    var isErrorEventWithoutError = isErrorEvent(ex) && !ex.error;

    if (isNotError && isNotErrorEvent || isErrorEventWithoutError) {
      return this.captureMessage(ex, objectMerge({
        trimHeadFrames: 1,
        stacktrace: true // if we fall back to captureMessage, default to attempting a new trace
      }, options));
    }

    // Get actual Error from ErrorEvent
    if (isErrorEvent(ex)) ex = ex.error;

    // Store the raw exception object for potential debugging and introspection
    this._lastCapturedException = ex;

    // TraceKit.report will re-raise any exception passed to it,
    // which means you have to wrap it in try/catch. Instead, we
    // can wrap it here and only re-raise if TraceKit.report
    // raises an exception different from the one we asked to
    // report on.
    try {
      var stack = TraceKit.computeStackTrace(ex);
      this._handleStackInfo(stack, options);
    } catch (ex1) {
      if (ex !== ex1) {
        throw ex1;
      }
    }

    return this;
  },

  /*
     * Manually send a message to Sentry
     *
     * @param {string} msg A plain message to be captured in Sentry
     * @param {object} options A specific set of options for this message [optional]
     * @return {Raven}
     */
  captureMessage: function captureMessage(msg, options) {
    // config() automagically converts ignoreErrors from a list to a RegExp so we need to test for an
    // early call; we'll error on the side of logging anything called before configuration since it's
    // probably something you should see:
    if (!!this._globalOptions.ignoreErrors.test && this._globalOptions.ignoreErrors.test(msg)) {
      return;
    }

    options = options || {};

    var data = objectMerge({
      message: msg + '' // Make sure it's actually a string
    }, options);

    var ex;
    // Generate a "synthetic" stack trace from this point.
    // NOTE: If you are a Sentry user, and you are seeing this stack frame, it is NOT indicative
    //       of a bug with Raven.js. Sentry generates synthetic traces either by configuration,
    //       or if it catches a thrown object without a "stack" property.
    try {
      throw new Error(msg);
    } catch (ex1) {
      ex = ex1;
    }

    // null exception name so `Error` isn't prefixed to msg
    ex.name = null;
    var stack = TraceKit.computeStackTrace(ex);

    // stack[0] is `throw new Error(msg)` call itself, we are interested in the frame that was just before that, stack[1]
    var initialCall = isArray(stack.stack) && stack.stack[1];
    var fileurl = initialCall && initialCall.url || '';

    if (!!this._globalOptions.ignoreUrls.test && this._globalOptions.ignoreUrls.test(fileurl)) {
      return;
    }

    if (!!this._globalOptions.whitelistUrls.test && !this._globalOptions.whitelistUrls.test(fileurl)) {
      return;
    }

    if (this._globalOptions.stacktrace || options && options.stacktrace) {
      options = objectMerge({
        // fingerprint on msg, not stack trace (legacy behavior, could be
        // revisited)
        fingerprint: msg,
        // since we know this is a synthetic trace, the top N-most frames
        // MUST be from Raven.js, so mark them as in_app later by setting
        // trimHeadFrames
        trimHeadFrames: (options.trimHeadFrames || 0) + 1
      }, options);

      var frames = this._prepareFrames(stack, options);
      data.stacktrace = {
        // Sentry expects frames oldest to newest
        frames: frames.reverse()
      };
    }

    // Fire away!
    this._send(data);

    return this;
  },

  captureBreadcrumb: function captureBreadcrumb(obj) {
    var crumb = objectMerge({
      timestamp: now() / 1000
    }, obj);

    if (isFunction(this._globalOptions.breadcrumbCallback)) {
      var result = this._globalOptions.breadcrumbCallback(crumb);

      if (isObject(result) && !isEmptyObject(result)) {
        crumb = result;
      } else if (result === false) {
        return this;
      }
    }

    this._breadcrumbs.push(crumb);
    if (this._breadcrumbs.length > this._globalOptions.maxBreadcrumbs) {
      this._breadcrumbs.shift();
    }
    return this;
  },

  addPlugin: function addPlugin(plugin /*arg1, arg2, ... argN*/) {
    var pluginArgs = [].slice.call(arguments, 1);

    this._plugins.push([plugin, pluginArgs]);
    if (this._isRavenInstalled) {
      this._drainPlugins();
    }

    return this;
  },

  /*
     * Set/clear a user to be sent along with the payload.
     *
     * @param {object} user An object representing user data [optional]
     * @return {Raven}
     */
  setUserContext: function setUserContext(user) {
    // Intentionally do not merge here since that's an unexpected behavior.
    this._globalContext.user = user;

    return this;
  },

  /*
     * Merge extra attributes to be sent along with the payload.
     *
     * @param {object} extra An object representing extra data [optional]
     * @return {Raven}
     */
  setExtraContext: function setExtraContext(extra) {
    this._mergeContext('extra', extra);

    return this;
  },

  /*
     * Merge tags to be sent along with the payload.
     *
     * @param {object} tags An object representing tags [optional]
     * @return {Raven}
     */
  setTagsContext: function setTagsContext(tags) {
    this._mergeContext('tags', tags);

    return this;
  },

  /*
     * Clear all of the context.
     *
     * @return {Raven}
     */
  clearContext: function clearContext() {
    this._globalContext = {};

    return this;
  },

  /*
     * Get a copy of the current context. This cannot be mutated.
     *
     * @return {object} copy of context
     */
  getContext: function getContext() {
    // lol javascript
    return JSON.parse(stringify(this._globalContext));
  },

  /*
     * Set environment of application
     *
     * @param {string} environment Typically something like 'production'.
     * @return {Raven}
     */
  setEnvironment: function setEnvironment(environment) {
    this._globalOptions.environment = environment;

    return this;
  },

  /*
     * Set release version of application
     *
     * @param {string} release Typically something like a git SHA to identify version
     * @return {Raven}
     */
  setRelease: function setRelease(release) {
    this._globalOptions.release = release;

    return this;
  },

  /*
     * Set the dataCallback option
     *
     * @param {function} callback The callback to run which allows the
     *                            data blob to be mutated before sending
     * @return {Raven}
     */
  setDataCallback: function setDataCallback(callback) {
    var original = this._globalOptions.dataCallback;
    this._globalOptions.dataCallback = keepOriginalCallback(original, callback);
    return this;
  },

  /*
     * Set the breadcrumbCallback option
     *
     * @param {function} callback The callback to run which allows filtering
     *                            or mutating breadcrumbs
     * @return {Raven}
     */
  setBreadcrumbCallback: function setBreadcrumbCallback(callback) {
    var original = this._globalOptions.breadcrumbCallback;
    this._globalOptions.breadcrumbCallback = keepOriginalCallback(original, callback);
    return this;
  },

  /*
     * Set the shouldSendCallback option
     *
     * @param {function} callback The callback to run which allows
     *                            introspecting the blob before sending
     * @return {Raven}
     */
  setShouldSendCallback: function setShouldSendCallback(callback) {
    var original = this._globalOptions.shouldSendCallback;
    this._globalOptions.shouldSendCallback = keepOriginalCallback(original, callback);
    return this;
  },

  /**
     * Override the default HTTP transport mechanism that transmits data
     * to the Sentry server.
     *
     * @param {function} transport Function invoked instead of the default
     *                             `makeRequest` handler.
     *
     * @return {Raven}
     */
  setTransport: function setTransport(transport) {
    this._globalOptions.transport = transport;

    return this;
  },

  /*
     * Get the latest raw exception that was captured by Raven.
     *
     * @return {error}
     */
  lastException: function lastException() {
    return this._lastCapturedException;
  },

  /*
     * Get the last event id
     *
     * @return {string}
     */
  lastEventId: function lastEventId() {
    return this._lastEventId;
  },

  /*
     * Determine if Raven is setup and ready to go.
     *
     * @return {boolean}
     */
  isSetup: function isSetup() {
    if (!this._hasJSON) return false; // needs JSON support
    if (!this._globalServer) {
      if (!this.ravenNotConfiguredError) {
        this.ravenNotConfiguredError = true;
        this._logDebug('error', 'Error: Raven has not been configured.');
      }
      return false;
    }
    return true;
  },

  afterLoad: function afterLoad() {
    // TODO: remove window dependence?

    // Attempt to initialize Raven on load
    var RavenConfig = _window.RavenConfig;
    if (RavenConfig) {
      this.config(RavenConfig.dsn, RavenConfig.config).install();
    }
  },

  showReportDialog: function showReportDialog(options) {
    if (!_document // doesn't work without a document (React native)
    ) return;

    options = options || {};

    var lastEventId = options.eventId || this.lastEventId();
    if (!lastEventId) {
      throw new RavenConfigError('Missing eventId');
    }

    var dsn = options.dsn || this._dsn;
    if (!dsn) {
      throw new RavenConfigError('Missing DSN');
    }

    var encode = encodeURIComponent;
    var qs = '';
    qs += '?eventId=' + encode(lastEventId);
    qs += '&dsn=' + encode(dsn);

    var user = options.user || this._globalContext.user;
    if (user) {
      if (user.name) qs += '&name=' + encode(user.name);
      if (user.email) qs += '&email=' + encode(user.email);
    }

    var globalServer = this._getGlobalServer(this._parseDSN(dsn));

    var script = _document.createElement('script');
    script.async = true;
    script.src = globalServer + '/api/embed/error-page/' + qs;
    (_document.head || _document.body).appendChild(script);
  },

  /**** Private functions ****/
  _ignoreNextOnError: function _ignoreNextOnError() {
    var self = this;
    this._ignoreOnError += 1;
    setTimeout(function () {
      // onerror should trigger before setTimeout
      self._ignoreOnError -= 1;
    });
  },

  _triggerEvent: function _triggerEvent(eventType, options) {
    // NOTE: `event` is a native browser thing, so let's avoid conflicting wiht it
    var evt, key;

    if (!this._hasDocument) return;

    options = options || {};

    eventType = 'raven' + eventType.substr(0, 1).toUpperCase() + eventType.substr(1);

    if (_document.createEvent) {
      evt = _document.createEvent('HTMLEvents');
      evt.initEvent(eventType, true, true);
    } else {
      evt = _document.createEventObject();
      evt.eventType = eventType;
    }

    for (key in options) {
      if (hasKey(options, key)) {
        evt[key] = options[key];
      }
    }if (_document.createEvent) {
      // IE9 if standards
      _document.dispatchEvent(evt);
    } else {
      // IE8 regardless of Quirks or Standards
      // IE9 if quirks
      try {
        _document.fireEvent('on' + evt.eventType.toLowerCase(), evt);
      } catch (e) {
        // Do nothing
      }
    }
  },

  /**
     * Wraps addEventListener to capture UI breadcrumbs
     * @param evtName the event name (e.g. "click")
     * @returns {Function}
     * @private
     */
  _breadcrumbEventHandler: function _breadcrumbEventHandler(evtName) {
    var self = this;
    return function (evt) {
      // reset keypress timeout; e.g. triggering a 'click' after
      // a 'keypress' will reset the keypress debounce so that a new
      // set of keypresses can be recorded
      self._keypressTimeout = null;

      // It's possible this handler might trigger multiple times for the same
      // event (e.g. event propagation through node ancestors). Ignore if we've
      // already captured the event.
      if (self._lastCapturedEvent === evt) return;

      self._lastCapturedEvent = evt;

      // try/catch both:
      // - accessing evt.target (see getsentry/raven-js#838, #768)
      // - `htmlTreeAsString` because it's complex, and just accessing the DOM incorrectly
      //   can throw an exception in some circumstances.
      var target;
      try {
        target = htmlTreeAsString(evt.target);
      } catch (e) {
        target = '<unknown>';
      }

      self.captureBreadcrumb({
        category: 'ui.' + evtName, // e.g. ui.click, ui.input
        message: target
      });
    };
  },

  /**
     * Wraps addEventListener to capture keypress UI events
     * @returns {Function}
     * @private
     */
  _keypressEventHandler: function _keypressEventHandler() {
    var self = this,
        debounceDuration = 1000; // milliseconds

    // TODO: if somehow user switches keypress target before
    //       debounce timeout is triggered, we will only capture
    //       a single breadcrumb from the FIRST target (acceptable?)
    return function (evt) {
      var target;
      try {
        target = evt.target;
      } catch (e) {
        // just accessing event properties can throw an exception in some rare circumstances
        // see: https://github.com/getsentry/raven-js/issues/838
        return;
      }
      var tagName = target && target.tagName;

      // only consider keypress events on actual input elements
      // this will disregard keypresses targeting body (e.g. tabbing
      // through elements, hotkeys, etc)
      if (!tagName || tagName !== 'INPUT' && tagName !== 'TEXTAREA' && !target.isContentEditable) return;

      // record first keypress in a series, but ignore subsequent
      // keypresses until debounce clears
      var timeout = self._keypressTimeout;
      if (!timeout) {
        self._breadcrumbEventHandler('input')(evt);
      }
      clearTimeout(timeout);
      self._keypressTimeout = setTimeout(function () {
        self._keypressTimeout = null;
      }, debounceDuration);
    };
  },

  /**
     * Captures a breadcrumb of type "navigation", normalizing input URLs
     * @param to the originating URL
     * @param from the target URL
     * @private
     */
  _captureUrlChange: function _captureUrlChange(from, to) {
    var parsedLoc = parseUrl(this._location.href);
    var parsedTo = parseUrl(to);
    var parsedFrom = parseUrl(from);

    // because onpopstate only tells you the "new" (to) value of location.href, and
    // not the previous (from) value, we need to track the value of the current URL
    // state ourselves
    this._lastHref = to;

    // Use only the path component of the URL if the URL matches the current
    // document (almost all the time when using pushState)
    if (parsedLoc.protocol === parsedTo.protocol && parsedLoc.host === parsedTo.host) to = parsedTo.relative;
    if (parsedLoc.protocol === parsedFrom.protocol && parsedLoc.host === parsedFrom.host) from = parsedFrom.relative;

    this.captureBreadcrumb({
      category: 'navigation',
      data: {
        to: to,
        from: from
      }
    });
  },

  _patchFunctionToString: function _patchFunctionToString() {
    var self = this;
    self._originalFunctionToString = Function.prototype.toString;
    // eslint-disable-next-line no-extend-native
    Function.prototype.toString = function () {
      if (typeof this === 'function' && this.__raven__) {
        return self._originalFunctionToString.apply(this.__orig__, arguments);
      }
      return self._originalFunctionToString.apply(this, arguments);
    };
  },

  _unpatchFunctionToString: function _unpatchFunctionToString() {
    if (this._originalFunctionToString) {
      // eslint-disable-next-line no-extend-native
      Function.prototype.toString = this._originalFunctionToString;
    }
  },

  /**
     * Wrap timer functions and event targets to catch errors and provide
     * better metadata.
     */
  _instrumentTryCatch: function _instrumentTryCatch() {
    var self = this;

    var wrappedBuiltIns = self._wrappedBuiltIns;

    function wrapTimeFn(orig) {
      return function (fn, t) {
        // preserve arity
        // Make a copy of the arguments to prevent deoptimization
        // https://github.com/petkaantonov/bluebird/wiki/Optimization-killers#32-leaking-arguments
        var args = new Array(arguments.length);
        for (var i = 0; i < args.length; ++i) {
          args[i] = arguments[i];
        }
        var originalCallback = args[0];
        if (isFunction(originalCallback)) {
          args[0] = self.wrap(originalCallback);
        }

        // IE < 9 doesn't support .call/.apply on setInterval/setTimeout, but it
        // also supports only two arguments and doesn't care what this is, so we
        // can just call the original function directly.
        if (orig.apply) {
          return orig.apply(this, args);
        } else {
          return orig(args[0], args[1]);
        }
      };
    }

    var autoBreadcrumbs = this._globalOptions.autoBreadcrumbs;

    function wrapEventTarget(global) {
      var proto = _window[global] && _window[global].prototype;
      if (proto && proto.hasOwnProperty && proto.hasOwnProperty('addEventListener')) {
        fill(proto, 'addEventListener', function (orig) {
          return function (evtName, fn, capture, secure) {
            // preserve arity
            try {
              if (fn && fn.handleEvent) {
                fn.handleEvent = self.wrap(fn.handleEvent);
              }
            } catch (err) {}
            // can sometimes get 'Permission denied to access property "handle Event'


            // More breadcrumb DOM capture ... done here and not in `_instrumentBreadcrumbs`
            // so that we don't have more than one wrapper function
            var before, clickHandler, keypressHandler;

            if (autoBreadcrumbs && autoBreadcrumbs.dom && (global === 'EventTarget' || global === 'Node')) {
              // NOTE: generating multiple handlers per addEventListener invocation, should
              //       revisit and verify we can just use one (almost certainly)
              clickHandler = self._breadcrumbEventHandler('click');
              keypressHandler = self._keypressEventHandler();
              before = function before(evt) {
                // need to intercept every DOM event in `before` argument, in case that
                // same wrapped method is re-used for different events (e.g. mousemove THEN click)
                // see #724
                if (!evt) return;

                var eventType;
                try {
                  eventType = evt.type;
                } catch (e) {
                  // just accessing event properties can throw an exception in some rare circumstances
                  // see: https://github.com/getsentry/raven-js/issues/838
                  return;
                }
                if (eventType === 'click') return clickHandler(evt);else if (eventType === 'keypress') return keypressHandler(evt);
              };
            }
            return orig.call(this, evtName, self.wrap(fn, undefined, before), capture, secure);
          };
        }, wrappedBuiltIns);
        fill(proto, 'removeEventListener', function (orig) {
          return function (evt, fn, capture, secure) {
            try {
              fn = fn && (fn.__raven_wrapper__ ? fn.__raven_wrapper__ : fn);
            } catch (e) {
              // ignore, accessing __raven_wrapper__ will throw in some Selenium environments
            }
            return orig.call(this, evt, fn, capture, secure);
          };
        }, wrappedBuiltIns);
      }
    }

    fill(_window, 'setTimeout', wrapTimeFn, wrappedBuiltIns);
    fill(_window, 'setInterval', wrapTimeFn, wrappedBuiltIns);
    if (_window.requestAnimationFrame) {
      fill(_window, 'requestAnimationFrame', function (orig) {
        return function (cb) {
          return orig(self.wrap(cb));
        };
      }, wrappedBuiltIns);
    }

    // event targets borrowed from bugsnag-js:
    // https://github.com/bugsnag/bugsnag-js/blob/master/src/bugsnag.js#L666
    var eventTargets = ['EventTarget', 'Window', 'Node', 'ApplicationCache', 'AudioTrackList', 'ChannelMergerNode', 'CryptoOperation', 'EventSource', 'FileReader', 'HTMLUnknownElement', 'IDBDatabase', 'IDBRequest', 'IDBTransaction', 'KeyOperation', 'MediaController', 'MessagePort', 'ModalWindow', 'Notification', 'SVGElementInstance', 'Screen', 'TextTrack', 'TextTrackCue', 'TextTrackList', 'WebSocket', 'WebSocketWorker', 'Worker', 'XMLHttpRequest', 'XMLHttpRequestEventTarget', 'XMLHttpRequestUpload'];
    for (var i = 0; i < eventTargets.length; i++) {
      wrapEventTarget(eventTargets[i]);
    }
  },

  /**
     * Instrument browser built-ins w/ breadcrumb capturing
     *  - XMLHttpRequests
     *  - DOM interactions (click/typing)
     *  - window.location changes
     *  - console
     *
     * Can be disabled or individually configured via the `autoBreadcrumbs` config option
     */
  _instrumentBreadcrumbs: function _instrumentBreadcrumbs() {
    var self = this;
    var autoBreadcrumbs = this._globalOptions.autoBreadcrumbs;

    var wrappedBuiltIns = self._wrappedBuiltIns;

    function wrapProp(prop, xhr) {
      if (prop in xhr && isFunction(xhr[prop])) {
        fill(xhr, prop, function (orig) {
          return self.wrap(orig);
        }); // intentionally don't track filled methods on XHR instances
      }
    }

    if (autoBreadcrumbs.xhr && 'XMLHttpRequest' in _window) {
      var xhrproto = XMLHttpRequest.prototype;
      fill(xhrproto, 'open', function (origOpen) {
        return function (method, url) {
          // preserve arity

          // if Sentry key appears in URL, don't capture
          if (isString(url) && url.indexOf(self._globalKey) === -1) {
            this.__raven_xhr = {
              method: method,
              url: url,
              status_code: null
            };
          }

          return origOpen.apply(this, arguments);
        };
      }, wrappedBuiltIns);

      fill(xhrproto, 'send', function (origSend) {
        return function (data) {
          // preserve arity
          var xhr = this;

          function onreadystatechangeHandler() {
            if (xhr.__raven_xhr && xhr.readyState === 4) {
              try {
                // touching statusCode in some platforms throws
                // an exception
                xhr.__raven_xhr.status_code = xhr.status;
              } catch (e) {
                /* do nothing */
              }

              self.captureBreadcrumb({
                type: 'http',
                category: 'xhr',
                data: xhr.__raven_xhr
              });
            }
          }

          var props = ['onload', 'onerror', 'onprogress'];
          for (var j = 0; j < props.length; j++) {
            wrapProp(props[j], xhr);
          }

          if ('onreadystatechange' in xhr && isFunction(xhr.onreadystatechange)) {
            fill(xhr, 'onreadystatechange', function (orig) {
              return self.wrap(orig, undefined, onreadystatechangeHandler);
            } /* intentionally don't track this instrumentation */
            );
          } else {
            // if onreadystatechange wasn't actually set by the page on this xhr, we
            // are free to set our own and capture the breadcrumb
            xhr.onreadystatechange = onreadystatechangeHandler;
          }

          return origSend.apply(this, arguments);
        };
      }, wrappedBuiltIns);
    }

    if (autoBreadcrumbs.xhr && 'fetch' in _window) {
      fill(_window, 'fetch', function (origFetch) {
        return function (fn, t) {
          // preserve arity
          // Make a copy of the arguments to prevent deoptimization
          // https://github.com/petkaantonov/bluebird/wiki/Optimization-killers#32-leaking-arguments
          var args = new Array(arguments.length);
          for (var i = 0; i < args.length; ++i) {
            args[i] = arguments[i];
          }

          var fetchInput = args[0];
          var method = 'GET';
          var url;

          if (typeof fetchInput === 'string') {
            url = fetchInput;
          } else if ('Request' in _window && fetchInput instanceof _window.Request) {
            url = fetchInput.url;
            if (fetchInput.method) {
              method = fetchInput.method;
            }
          } else {
            url = '' + fetchInput;
          }

          if (args[1] && args[1].method) {
            method = args[1].method;
          }

          var fetchData = {
            method: method,
            url: url,
            status_code: null
          };

          self.captureBreadcrumb({
            type: 'http',
            category: 'fetch',
            data: fetchData
          });

          return origFetch.apply(this, args).then(function (response) {
            fetchData.status_code = response.status;

            return response;
          });
        };
      }, wrappedBuiltIns);
    }

    // Capture breadcrumbs from any click that is unhandled / bubbled up all the way
    // to the document. Do this before we instrument addEventListener.
    if (autoBreadcrumbs.dom && this._hasDocument) {
      if (_document.addEventListener) {
        _document.addEventListener('click', self._breadcrumbEventHandler('click'), false);
        _document.addEventListener('keypress', self._keypressEventHandler(), false);
      } else {
        // IE8 Compatibility
        _document.attachEvent('onclick', self._breadcrumbEventHandler('click'));
        _document.attachEvent('onkeypress', self._keypressEventHandler());
      }
    }

    // record navigation (URL) changes
    // NOTE: in Chrome App environment, touching history.pushState, *even inside
    //       a try/catch block*, will cause Chrome to output an error to console.error
    // borrowed from: https://github.com/angular/angular.js/pull/13945/files
    var chrome = _window.chrome;
    var isChromePackagedApp = chrome && chrome.app && chrome.app.runtime;
    var hasPushAndReplaceState = !isChromePackagedApp && _window.history && history.pushState && history.replaceState;
    if (autoBreadcrumbs.location && hasPushAndReplaceState) {
      // TODO: remove onpopstate handler on uninstall()
      var oldOnPopState = _window.onpopstate;
      _window.onpopstate = function () {
        var currentHref = self._location.href;
        self._captureUrlChange(self._lastHref, currentHref);

        if (oldOnPopState) {
          return oldOnPopState.apply(this, arguments);
        }
      };

      var historyReplacementFunction = function historyReplacementFunction(origHistFunction) {
        // note history.pushState.length is 0; intentionally not declaring
        // params to preserve 0 arity
        return function () /* state, title, url */{
          var url = arguments.length > 2 ? arguments[2] : undefined;

          // url argument is optional
          if (url) {
            // coerce to string (this is what pushState does)
            self._captureUrlChange(self._lastHref, url + '');
          }

          return origHistFunction.apply(this, arguments);
        };
      };

      fill(history, 'pushState', historyReplacementFunction, wrappedBuiltIns);
      fill(history, 'replaceState', historyReplacementFunction, wrappedBuiltIns);
    }

    if (autoBreadcrumbs.console && 'console' in _window && console.log) {
      // console
      var consoleMethodCallback = function consoleMethodCallback(msg, data) {
        self.captureBreadcrumb({
          message: msg,
          level: data.level,
          category: 'console'
        });
      };

      each(['debug', 'info', 'warn', 'error', 'log'], function (_, level) {
        wrapConsoleMethod(console, level, consoleMethodCallback);
      });
    }
  },

  _restoreBuiltIns: function _restoreBuiltIns() {
    // restore any wrapped builtins
    var builtin;
    while (this._wrappedBuiltIns.length) {
      builtin = this._wrappedBuiltIns.shift();

      var obj = builtin[0],
          name = builtin[1],
          orig = builtin[2];

      obj[name] = orig;
    }
  },

  _drainPlugins: function _drainPlugins() {
    var self = this;

    // FIX ME TODO
    each(this._plugins, function (_, plugin) {
      var installer = plugin[0];
      var args = plugin[1];
      installer.apply(self, [self].concat(args));
    });
  },

  _parseDSN: function _parseDSN(str) {
    var m = dsnPattern.exec(str),
        dsn = {},
        i = 7;

    try {
      while (i--) {
        dsn[dsnKeys[i]] = m[i] || '';
      }
    } catch (e) {
      throw new RavenConfigError('Invalid DSN: ' + str);
    }

    if (dsn.pass && !this._globalOptions.allowSecretKey) {
      throw new RavenConfigError('Do not specify your secret key in the DSN. See: http://bit.ly/raven-secret-key');
    }

    return dsn;
  },

  _getGlobalServer: function _getGlobalServer(uri) {
    // assemble the endpoint from the uri pieces
    var globalServer = '//' + uri.host + (uri.port ? ':' + uri.port : '');

    if (uri.protocol) {
      globalServer = uri.protocol + ':' + globalServer;
    }
    return globalServer;
  },

  _handleOnErrorStackInfo: function _handleOnErrorStackInfo() {
    // if we are intentionally ignoring errors via onerror, bail out
    if (!this._ignoreOnError) {
      this._handleStackInfo.apply(this, arguments);
    }
  },

  _handleStackInfo: function _handleStackInfo(stackInfo, options) {
    var frames = this._prepareFrames(stackInfo, options);

    this._triggerEvent('handle', {
      stackInfo: stackInfo,
      options: options
    });

    this._processException(stackInfo.name, stackInfo.message, stackInfo.url, stackInfo.lineno, frames, options);
  },

  _prepareFrames: function _prepareFrames(stackInfo, options) {
    var self = this;
    var frames = [];
    if (stackInfo.stack && stackInfo.stack.length) {
      each(stackInfo.stack, function (i, stack) {
        var frame = self._normalizeFrame(stack, stackInfo.url);
        if (frame) {
          frames.push(frame);
        }
      });

      // e.g. frames captured via captureMessage throw
      if (options && options.trimHeadFrames) {
        for (var j = 0; j < options.trimHeadFrames && j < frames.length; j++) {
          frames[j].in_app = false;
        }
      }
    }
    frames = frames.slice(0, this._globalOptions.stackTraceLimit);
    return frames;
  },

  _normalizeFrame: function _normalizeFrame(frame, stackInfoUrl) {
    // normalize the frames data
    var normalized = {
      filename: frame.url,
      lineno: frame.line,
      colno: frame.column,
      function: frame.func || '?'
    };

    // Case when we don't have any information about the error
    // E.g. throwing a string or raw object, instead of an `Error` in Firefox
    // Generating synthetic error doesn't add any value here
    //
    // We should probably somehow let a user know that they should fix their code
    if (!frame.url) {
      normalized.filename = stackInfoUrl; // fallback to whole stacks url from onerror handler
    }

    normalized.in_app = !( // determine if an exception came from outside of our app
    // first we check the global includePaths list.
    !!this._globalOptions.includePaths.test && !this._globalOptions.includePaths.test(normalized.filename) ||
    // Now we check for fun, if the function name is Raven or TraceKit
    /(Raven|TraceKit)\./.test(normalized['function']) ||
    // finally, we do a last ditch effort and check for raven.min.js
    /raven\.(min\.)?js$/.test(normalized.filename));

    return normalized;
  },

  _processException: function _processException(type, message, fileurl, lineno, frames, options) {
    var prefixedMessage = (type ? type + ': ' : '') + (message || '');
    if (!!this._globalOptions.ignoreErrors.test && (this._globalOptions.ignoreErrors.test(message) || this._globalOptions.ignoreErrors.test(prefixedMessage))) {
      return;
    }

    var stacktrace;

    if (frames && frames.length) {
      fileurl = frames[0].filename || fileurl;
      // Sentry expects frames oldest to newest
      // and JS sends them as newest to oldest
      frames.reverse();
      stacktrace = { frames: frames };
    } else if (fileurl) {
      stacktrace = {
        frames: [{
          filename: fileurl,
          lineno: lineno,
          in_app: true
        }]
      };
    }

    if (!!this._globalOptions.ignoreUrls.test && this._globalOptions.ignoreUrls.test(fileurl)) {
      return;
    }

    if (!!this._globalOptions.whitelistUrls.test && !this._globalOptions.whitelistUrls.test(fileurl)) {
      return;
    }

    var data = objectMerge({
      // sentry.interfaces.Exception
      exception: {
        values: [{
          type: type,
          value: message,
          stacktrace: stacktrace
        }]
      },
      culprit: fileurl
    }, options);

    // Fire away!
    this._send(data);
  },

  _trimPacket: function _trimPacket(data) {
    // For now, we only want to truncate the two different messages
    // but this could/should be expanded to just trim everything
    var max = this._globalOptions.maxMessageLength;
    if (data.message) {
      data.message = truncate(data.message, max);
    }
    if (data.exception) {
      var exception = data.exception.values[0];
      exception.value = truncate(exception.value, max);
    }

    var request = data.request;
    if (request) {
      if (request.url) {
        request.url = truncate(request.url, this._globalOptions.maxUrlLength);
      }
      if (request.Referer) {
        request.Referer = truncate(request.Referer, this._globalOptions.maxUrlLength);
      }
    }

    if (data.breadcrumbs && data.breadcrumbs.values) this._trimBreadcrumbs(data.breadcrumbs);

    return data;
  },

  /**
     * Truncate breadcrumb values (right now just URLs)
     */
  _trimBreadcrumbs: function _trimBreadcrumbs(breadcrumbs) {
    // known breadcrumb properties with urls
    // TODO: also consider arbitrary prop values that start with (https?)?://
    var urlProps = ['to', 'from', 'url'],
        urlProp,
        crumb,
        data;

    for (var i = 0; i < breadcrumbs.values.length; ++i) {
      crumb = breadcrumbs.values[i];
      if (!crumb.hasOwnProperty('data') || !isObject(crumb.data) || objectFrozen(crumb.data)) continue;

      data = objectMerge({}, crumb.data);
      for (var j = 0; j < urlProps.length; ++j) {
        urlProp = urlProps[j];
        if (data.hasOwnProperty(urlProp) && data[urlProp]) {
          data[urlProp] = truncate(data[urlProp], this._globalOptions.maxUrlLength);
        }
      }
      breadcrumbs.values[i].data = data;
    }
  },

  _getHttpData: function _getHttpData() {
    if (!this._hasNavigator && !this._hasDocument) return;
    var httpData = {};

    if (this._hasNavigator && _navigator.userAgent) {
      httpData.headers = {
        'User-Agent': navigator.userAgent
      };
    }

    if (this._hasDocument) {
      if (_document.location && _document.location.href) {
        httpData.url = _document.location.href;
      }
      if (_document.referrer) {
        if (!httpData.headers) httpData.headers = {};
        httpData.headers.Referer = _document.referrer;
      }
    }

    return httpData;
  },

  _resetBackoff: function _resetBackoff() {
    this._backoffDuration = 0;
    this._backoffStart = null;
  },

  _shouldBackoff: function _shouldBackoff() {
    return this._backoffDuration && now() - this._backoffStart < this._backoffDuration;
  },

  /**
     * Returns true if the in-process data payload matches the signature
     * of the previously-sent data
     *
     * NOTE: This has to be done at this level because TraceKit can generate
     *       data from window.onerror WITHOUT an exception object (IE8, IE9,
     *       other old browsers). This can take the form of an "exception"
     *       data object with a single frame (derived from the onerror args).
     */
  _isRepeatData: function _isRepeatData(current) {
    var last = this._lastData;

    if (!last || current.message !== last.message || // defined for captureMessage
    current.culprit !== last.culprit // defined for captureException/onerror
    ) return false;

    // Stacktrace interface (i.e. from captureMessage)
    if (current.stacktrace || last.stacktrace) {
      return isSameStacktrace(current.stacktrace, last.stacktrace);
    } else if (current.exception || last.exception) {
      // Exception interface (i.e. from captureException/onerror)
      return isSameException(current.exception, last.exception);
    }

    return true;
  },

  _setBackoffState: function _setBackoffState(request) {
    // If we are already in a backoff state, don't change anything
    if (this._shouldBackoff()) {
      return;
    }

    var status = request.status;

    // 400 - project_id doesn't exist or some other fatal
    // 401 - invalid/revoked dsn
    // 429 - too many requests
    if (!(status === 400 || status === 401 || status === 429)) return;

    var retry;
    try {
      // If Retry-After is not in Access-Control-Expose-Headers, most
      // browsers will throw an exception trying to access it
      retry = request.getResponseHeader('Retry-After');
      retry = parseInt(retry, 10) * 1000; // Retry-After is returned in seconds
    } catch (e) {
      /* eslint no-empty:0 */
    }

    this._backoffDuration = retry ? // If Sentry server returned a Retry-After value, use it
    retry : // Otherwise, double the last backoff duration (starts at 1 sec)
    this._backoffDuration * 2 || 1000;

    this._backoffStart = now();
  },

  _send: function _send(data) {
    var globalOptions = this._globalOptions;

    var baseData = {
      project: this._globalProject,
      logger: globalOptions.logger,
      platform: 'javascript'
    },
        httpData = this._getHttpData();

    if (httpData) {
      baseData.request = httpData;
    }

    // HACK: delete `trimHeadFrames` to prevent from appearing in outbound payload
    if (data.trimHeadFrames) delete data.trimHeadFrames;

    data = objectMerge(baseData, data);

    // Merge in the tags and extra separately since objectMerge doesn't handle a deep merge
    data.tags = objectMerge(objectMerge({}, this._globalContext.tags), data.tags);
    data.extra = objectMerge(objectMerge({}, this._globalContext.extra), data.extra);

    // Send along our own collected metadata with extra
    data.extra['session:duration'] = now() - this._startTime;

    if (this._breadcrumbs && this._breadcrumbs.length > 0) {
      // intentionally make shallow copy so that additions
      // to breadcrumbs aren't accidentally sent in this request
      data.breadcrumbs = {
        values: [].slice.call(this._breadcrumbs, 0)
      };
    }

    // If there are no tags/extra, strip the key from the payload alltogther.
    if (isEmptyObject(data.tags)) delete data.tags;

    if (this._globalContext.user) {
      // sentry.interfaces.User
      data.user = this._globalContext.user;
    }

    // Include the environment if it's defined in globalOptions
    if (globalOptions.environment) data.environment = globalOptions.environment;

    // Include the release if it's defined in globalOptions
    if (globalOptions.release) data.release = globalOptions.release;

    // Include server_name if it's defined in globalOptions
    if (globalOptions.serverName) data.server_name = globalOptions.serverName;

    if (isFunction(globalOptions.dataCallback)) {
      data = globalOptions.dataCallback(data) || data;
    }

    // Why??????????
    if (!data || isEmptyObject(data)) {
      return;
    }

    // Check if the request should be filtered or not
    if (isFunction(globalOptions.shouldSendCallback) && !globalOptions.shouldSendCallback(data)) {
      return;
    }

    // Backoff state: Sentry server previously responded w/ an error (e.g. 429 - too many requests),
    // so drop requests until "cool-off" period has elapsed.
    if (this._shouldBackoff()) {
      this._logDebug('warn', 'Raven dropped error due to backoff: ', data);
      return;
    }

    if (typeof globalOptions.sampleRate === 'number') {
      if (Math.random() < globalOptions.sampleRate) {
        this._sendProcessedPayload(data);
      }
    } else {
      this._sendProcessedPayload(data);
    }
  },

  _getUuid: function _getUuid() {
    return uuid4();
  },

  _sendProcessedPayload: function _sendProcessedPayload(data, callback) {
    var self = this;
    var globalOptions = this._globalOptions;

    if (!this.isSetup()) return;

    // Try and clean up the packet before sending by truncating long values
    data = this._trimPacket(data);

    // ideally duplicate error testing should occur *before* dataCallback/shouldSendCallback,
    // but this would require copying an un-truncated copy of the data packet, which can be
    // arbitrarily deep (extra_data) -- could be worthwhile? will revisit
    if (!this._globalOptions.allowDuplicates && this._isRepeatData(data)) {
      this._logDebug('warn', 'Raven dropped repeat event: ', data);
      return;
    }

    // Send along an event_id if not explicitly passed.
    // This event_id can be used to reference the error within Sentry itself.
    // Set lastEventId after we know the error should actually be sent
    this._lastEventId = data.event_id || (data.event_id = this._getUuid());

    // Store outbound payload after trim
    this._lastData = data;

    this._logDebug('debug', 'Raven about to send:', data);

    var auth = {
      sentry_version: '7',
      sentry_client: 'raven-js/' + this.VERSION,
      sentry_key: this._globalKey
    };

    if (this._globalSecret) {
      auth.sentry_secret = this._globalSecret;
    }

    var exception = data.exception && data.exception.values[0];

    // only capture 'sentry' breadcrumb is autoBreadcrumbs is truthy
    if (this._globalOptions.autoBreadcrumbs && this._globalOptions.autoBreadcrumbs.sentry) {
      this.captureBreadcrumb({
        category: 'sentry',
        message: exception ? (exception.type ? exception.type + ': ' : '') + exception.value : data.message,
        event_id: data.event_id,
        level: data.level || 'error' // presume error unless specified
      });
    }

    var url = this._globalEndpoint;
    (globalOptions.transport || this._makeRequest).call(this, {
      url: url,
      auth: auth,
      data: data,
      options: globalOptions,
      onSuccess: function success() {
        self._resetBackoff();

        self._triggerEvent('success', {
          data: data,
          src: url
        });
        callback && callback();
      },
      onError: function failure(error) {
        self._logDebug('error', 'Raven transport failed to send: ', error);

        if (error.request) {
          self._setBackoffState(error.request);
        }

        self._triggerEvent('failure', {
          data: data,
          src: url
        });
        error = error || new Error('Raven send failed (no additional details provided)');
        callback && callback(error);
      }
    });
  },

  _makeRequest: function _makeRequest(opts) {
    var request = _window.XMLHttpRequest && new _window.XMLHttpRequest();
    if (!request) return;

    // if browser doesn't support CORS (e.g. IE7), we are out of luck
    var hasCORS = 'withCredentials' in request || typeof XDomainRequest !== 'undefined';

    if (!hasCORS) return;

    var url = opts.url;

    if ('withCredentials' in request) {
      request.onreadystatechange = function () {
        if (request.readyState !== 4) {
          return;
        } else if (request.status === 200) {
          opts.onSuccess && opts.onSuccess();
        } else if (opts.onError) {
          var err = new Error('Sentry error code: ' + request.status);
          err.request = request;
          opts.onError(err);
        }
      };
    } else {
      request = new XDomainRequest();
      // xdomainrequest cannot go http -> https (or vice versa),
      // so always use protocol relative
      url = url.replace(/^https?:/, '');

      // onreadystatechange not supported by XDomainRequest
      if (opts.onSuccess) {
        request.onload = opts.onSuccess;
      }
      if (opts.onError) {
        request.onerror = function () {
          var err = new Error('Sentry error code: XDomainRequest');
          err.request = request;
          opts.onError(err);
        };
      }
    }

    // NOTE: auth is intentionally sent as part of query string (NOT as custom
    //       HTTP header) so as to avoid preflight CORS requests
    request.open('POST', url + '?' + urlencode(opts.auth));
    request.send(stringify(opts.data));
  },

  _logDebug: function _logDebug(level) {
    if (this._originalConsoleMethods[level] && this.debug) {
      // In IE<10 console methods do not have their own 'apply' method
      Function.prototype.apply.call(this._originalConsoleMethods[level], this._originalConsole, [].slice.call(arguments, 1));
    }
  },

  _mergeContext: function _mergeContext(key, context) {
    if (isUndefined(context)) {
      delete this._globalContext[key];
    } else {
      this._globalContext[key] = objectMerge(this._globalContext[key] || {}, context);
    }
  }
};

// Deprecations
Raven.prototype.setUser = Raven.prototype.setUserContext;
Raven.prototype.setReleaseContext = Raven.prototype.setRelease;

module.exports = Raven;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"../vendor/TraceKit/tracekit":12,"../vendor/json-stringify-safe/stringify":13,"./configError":7,"./console":8,"./utils":11}],10:[function(require,module,exports){
(function (global){
'use strict';

/**
 * Enforces a single instance of the Raven client, and the
 * main entry point for Raven. If you are a consumer of the
 * Raven library, you SHOULD load this file (vs raven.js).
 **/

var RavenConstructor = require('./raven');

// This is to be defensive in environments where window does not exist (see https://github.com/getsentry/raven-js/pull/785)
var _window = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};
var _Raven = _window.Raven;

var Raven = new RavenConstructor();

/*
 * Allow multiple versions of Raven to be installed.
 * Strip Raven from the global context and returns the instance.
 *
 * @return {Raven}
 */
Raven.noConflict = function () {
  _window.Raven = _Raven;
  return Raven;
};

Raven.afterLoad();

module.exports = Raven;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./raven":9}],11:[function(require,module,exports){
(function (global){
'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _window = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

function isObject(what) {
  return (typeof what === 'undefined' ? 'undefined' : _typeof(what)) === 'object' && what !== null;
}

// Yanked from https://git.io/vS8DV re-used under CC0
// with some tiny modifications
function isError(value) {
  switch ({}.toString.call(value)) {
    case '[object Error]':
      return true;
    case '[object Exception]':
      return true;
    case '[object DOMException]':
      return true;
    default:
      return value instanceof Error;
  }
}

function isErrorEvent(value) {
  return supportsErrorEvent() && {}.toString.call(value) === '[object ErrorEvent]';
}

function isUndefined(what) {
  return what === void 0;
}

function isFunction(what) {
  return typeof what === 'function';
}

function isString(what) {
  return Object.prototype.toString.call(what) === '[object String]';
}

function isArray(what) {
  return Object.prototype.toString.call(what) === '[object Array]';
}

function isEmptyObject(what) {
  for (var _ in what) {
    if (what.hasOwnProperty(_)) {
      return false;
    }
  }
  return true;
}

function supportsErrorEvent() {
  try {
    new ErrorEvent(''); // eslint-disable-line no-new
    return true;
  } catch (e) {
    return false;
  }
}

function wrappedCallback(callback) {
  function dataCallback(data, original) {
    var normalizedData = callback(data) || data;
    if (original) {
      return original(normalizedData) || normalizedData;
    }
    return normalizedData;
  }

  return dataCallback;
}

function each(obj, callback) {
  var i, j;

  if (isUndefined(obj.length)) {
    for (i in obj) {
      if (hasKey(obj, i)) {
        callback.call(null, i, obj[i]);
      }
    }
  } else {
    j = obj.length;
    if (j) {
      for (i = 0; i < j; i++) {
        callback.call(null, i, obj[i]);
      }
    }
  }
}

function objectMerge(obj1, obj2) {
  if (!obj2) {
    return obj1;
  }
  each(obj2, function (key, value) {
    obj1[key] = value;
  });
  return obj1;
}

/**
 * This function is only used for react-native.
 * react-native freezes object that have already been sent over the
 * js bridge. We need this function in order to check if the object is frozen.
 * So it's ok that objectFrozen returns false if Object.isFrozen is not
 * supported because it's not relevant for other "platforms". See related issue:
 * https://github.com/getsentry/react-native-sentry/issues/57
 */
function objectFrozen(obj) {
  if (!Object.isFrozen) {
    return false;
  }
  return Object.isFrozen(obj);
}

function truncate(str, max) {
  return !max || str.length <= max ? str : str.substr(0, max) + '\u2026';
}

/**
 * hasKey, a better form of hasOwnProperty
 * Example: hasKey(MainHostObject, property) === true/false
 *
 * @param {Object} host object to check property
 * @param {string} key to check
 */
function hasKey(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function joinRegExp(patterns) {
  // Combine an array of regular expressions and strings into one large regexp
  // Be mad.
  var sources = [],
      i = 0,
      len = patterns.length,
      pattern;

  for (; i < len; i++) {
    pattern = patterns[i];
    if (isString(pattern)) {
      // If it's a string, we need to escape it
      // Taken from: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions
      sources.push(pattern.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, '\\$1'));
    } else if (pattern && pattern.source) {
      // If it's a regexp already, we want to extract the source
      sources.push(pattern.source);
    }
    // Intentionally skip other cases
  }
  return new RegExp(sources.join('|'), 'i');
}

function urlencode(o) {
  var pairs = [];
  each(o, function (key, value) {
    pairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
  });
  return pairs.join('&');
}

// borrowed from https://tools.ietf.org/html/rfc3986#appendix-B
// intentionally using regex and not <a/> href parsing trick because React Native and other
// environments where DOM might not be available
function parseUrl(url) {
  var match = url.match(/^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?$/);
  if (!match) return {};

  // coerce to undefined values to empty string so we don't get 'undefined'
  var query = match[6] || '';
  var fragment = match[8] || '';
  return {
    protocol: match[2],
    host: match[4],
    path: match[5],
    relative: match[5] + query + fragment // everything minus origin
  };
}
function uuid4() {
  var crypto = _window.crypto || _window.msCrypto;

  if (!isUndefined(crypto) && crypto.getRandomValues) {
    // Use window.crypto API if available
    // eslint-disable-next-line no-undef
    var arr = new Uint16Array(8);
    crypto.getRandomValues(arr);

    // set 4 in byte 7
    arr[3] = arr[3] & 0xfff | 0x4000;
    // set 2 most significant bits of byte 9 to '10'
    arr[4] = arr[4] & 0x3fff | 0x8000;

    var pad = function pad(num) {
      var v = num.toString(16);
      while (v.length < 4) {
        v = '0' + v;
      }
      return v;
    };

    return pad(arr[0]) + pad(arr[1]) + pad(arr[2]) + pad(arr[3]) + pad(arr[4]) + pad(arr[5]) + pad(arr[6]) + pad(arr[7]);
  } else {
    // http://stackoverflow.com/questions/105034/how-to-create-a-guid-uuid-in-javascript/2117523#2117523
    return 'xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0,
          v = c === 'x' ? r : r & 0x3 | 0x8;
      return v.toString(16);
    });
  }
}

/**
 * Given a child DOM element, returns a query-selector statement describing that
 * and its ancestors
 * e.g. [HTMLElement] => body > div > input#foo.btn[name=baz]
 * @param elem
 * @returns {string}
 */
function htmlTreeAsString(elem) {
  /* eslint no-extra-parens:0*/
  var MAX_TRAVERSE_HEIGHT = 5,
      MAX_OUTPUT_LEN = 80,
      out = [],
      height = 0,
      len = 0,
      separator = ' > ',
      sepLength = separator.length,
      nextStr;

  while (elem && height++ < MAX_TRAVERSE_HEIGHT) {
    nextStr = htmlElementAsString(elem);
    // bail out if
    // - nextStr is the 'html' element
    // - the length of the string that would be created exceeds MAX_OUTPUT_LEN
    //   (ignore this limit if we are on the first iteration)
    if (nextStr === 'html' || height > 1 && len + out.length * sepLength + nextStr.length >= MAX_OUTPUT_LEN) {
      break;
    }

    out.push(nextStr);

    len += nextStr.length;
    elem = elem.parentNode;
  }

  return out.reverse().join(separator);
}

/**
 * Returns a simple, query-selector representation of a DOM element
 * e.g. [HTMLElement] => input#foo.btn[name=baz]
 * @param HTMLElement
 * @returns {string}
 */
function htmlElementAsString(elem) {
  var out = [],
      className,
      classes,
      key,
      attr,
      i;

  if (!elem || !elem.tagName) {
    return '';
  }

  out.push(elem.tagName.toLowerCase());
  if (elem.id) {
    out.push('#' + elem.id);
  }

  className = elem.className;
  if (className && isString(className)) {
    classes = className.split(/\s+/);
    for (i = 0; i < classes.length; i++) {
      out.push('.' + classes[i]);
    }
  }
  var attrWhitelist = ['type', 'name', 'title', 'alt'];
  for (i = 0; i < attrWhitelist.length; i++) {
    key = attrWhitelist[i];
    attr = elem.getAttribute(key);
    if (attr) {
      out.push('[' + key + '="' + attr + '"]');
    }
  }
  return out.join('');
}

/**
 * Returns true if either a OR b is truthy, but not both
 */
function isOnlyOneTruthy(a, b) {
  return !!(!!a ^ !!b);
}

/**
 * Returns true if the two input exception interfaces have the same content
 */
function isSameException(ex1, ex2) {
  if (isOnlyOneTruthy(ex1, ex2)) return false;

  ex1 = ex1.values[0];
  ex2 = ex2.values[0];

  if (ex1.type !== ex2.type || ex1.value !== ex2.value) return false;

  return isSameStacktrace(ex1.stacktrace, ex2.stacktrace);
}

/**
 * Returns true if the two input stack trace interfaces have the same content
 */
function isSameStacktrace(stack1, stack2) {
  if (isOnlyOneTruthy(stack1, stack2)) return false;

  var frames1 = stack1.frames;
  var frames2 = stack2.frames;

  // Exit early if frame count differs
  if (frames1.length !== frames2.length) return false;

  // Iterate through every frame; bail out if anything differs
  var a, b;
  for (var i = 0; i < frames1.length; i++) {
    a = frames1[i];
    b = frames2[i];
    if (a.filename !== b.filename || a.lineno !== b.lineno || a.colno !== b.colno || a['function'] !== b['function']) return false;
  }
  return true;
}

/**
 * Polyfill a method
 * @param obj object e.g. `document`
 * @param name method name present on object e.g. `addEventListener`
 * @param replacement replacement function
 * @param track {optional} record instrumentation to an array
 */
function fill(obj, name, replacement, track) {
  var orig = obj[name];
  obj[name] = replacement(orig);
  obj[name].__raven__ = true;
  obj[name].__orig__ = orig;
  if (track) {
    track.push([obj, name, orig]);
  }
}

module.exports = {
  isObject: isObject,
  isError: isError,
  isErrorEvent: isErrorEvent,
  isUndefined: isUndefined,
  isFunction: isFunction,
  isString: isString,
  isArray: isArray,
  isEmptyObject: isEmptyObject,
  supportsErrorEvent: supportsErrorEvent,
  wrappedCallback: wrappedCallback,
  each: each,
  objectMerge: objectMerge,
  truncate: truncate,
  objectFrozen: objectFrozen,
  hasKey: hasKey,
  joinRegExp: joinRegExp,
  urlencode: urlencode,
  uuid4: uuid4,
  htmlTreeAsString: htmlTreeAsString,
  htmlElementAsString: htmlElementAsString,
  isSameException: isSameException,
  isSameStacktrace: isSameStacktrace,
  parseUrl: parseUrl,
  fill: fill
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],12:[function(require,module,exports){
(function (global){
'use strict';

var utils = require('../../src/utils');

/*
 TraceKit - Cross brower stack traces

 This was originally forked from github.com/occ/TraceKit, but has since been
 largely re-written and is now maintained as part of raven-js.  Tests for
 this are in test/vendor.

 MIT license
*/

var TraceKit = {
  collectWindowErrors: true,
  debug: false
};

// This is to be defensive in environments where window does not exist (see https://github.com/getsentry/raven-js/pull/785)
var _window = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

// global reference to slice
var _slice = [].slice;
var UNKNOWN_FUNCTION = '?';

// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error#Error_types
var ERROR_TYPES_RE = /^(?:[Uu]ncaught (?:exception: )?)?(?:((?:Eval|Internal|Range|Reference|Syntax|Type|URI|)Error): )?(.*)$/;

function getLocationHref() {
  if (typeof document === 'undefined' || document.location == null) return '';

  return document.location.href;
}

/**
 * TraceKit.report: cross-browser processing of unhandled exceptions
 *
 * Syntax:
 *   TraceKit.report.subscribe(function(stackInfo) { ... })
 *   TraceKit.report.unsubscribe(function(stackInfo) { ... })
 *   TraceKit.report(exception)
 *   try { ...code... } catch(ex) { TraceKit.report(ex); }
 *
 * Supports:
 *   - Firefox: full stack trace with line numbers, plus column number
 *              on top frame; column number is not guaranteed
 *   - Opera:   full stack trace with line and column numbers
 *   - Chrome:  full stack trace with line and column numbers
 *   - Safari:  line and column number for the top frame only; some frames
 *              may be missing, and column number is not guaranteed
 *   - IE:      line and column number for the top frame only; some frames
 *              may be missing, and column number is not guaranteed
 *
 * In theory, TraceKit should work on all of the following versions:
 *   - IE5.5+ (only 8.0 tested)
 *   - Firefox 0.9+ (only 3.5+ tested)
 *   - Opera 7+ (only 10.50 tested; versions 9 and earlier may require
 *     Exceptions Have Stacktrace to be enabled in opera:config)
 *   - Safari 3+ (only 4+ tested)
 *   - Chrome 1+ (only 5+ tested)
 *   - Konqueror 3.5+ (untested)
 *
 * Requires TraceKit.computeStackTrace.
 *
 * Tries to catch all unhandled exceptions and report them to the
 * subscribed handlers. Please note that TraceKit.report will rethrow the
 * exception. This is REQUIRED in order to get a useful stack trace in IE.
 * If the exception does not reach the top of the browser, you will only
 * get a stack trace from the point where TraceKit.report was called.
 *
 * Handlers receive a stackInfo object as described in the
 * TraceKit.computeStackTrace docs.
 */
TraceKit.report = function reportModuleWrapper() {
  var handlers = [],
      lastArgs = null,
      lastException = null,
      lastExceptionStack = null;

  /**
     * Add a crash handler.
     * @param {Function} handler
     */
  function subscribe(handler) {
    installGlobalHandler();
    handlers.push(handler);
  }

  /**
     * Remove a crash handler.
     * @param {Function} handler
     */
  function unsubscribe(handler) {
    for (var i = handlers.length - 1; i >= 0; --i) {
      if (handlers[i] === handler) {
        handlers.splice(i, 1);
      }
    }
  }

  /**
     * Remove all crash handlers.
     */
  function unsubscribeAll() {
    uninstallGlobalHandler();
    handlers = [];
  }

  /**
     * Dispatch stack information to all handlers.
     * @param {Object.<string, *>} stack
     */
  function notifyHandlers(stack, isWindowError) {
    var exception = null;
    if (isWindowError && !TraceKit.collectWindowErrors) {
      return;
    }
    for (var i in handlers) {
      if (handlers.hasOwnProperty(i)) {
        try {
          handlers[i].apply(null, [stack].concat(_slice.call(arguments, 2)));
        } catch (inner) {
          exception = inner;
        }
      }
    }

    if (exception) {
      throw exception;
    }
  }

  var _oldOnerrorHandler, _onErrorHandlerInstalled;

  /**
     * Ensures all global unhandled exceptions are recorded.
     * Supported by Gecko and IE.
     * @param {string} message Error message.
     * @param {string} url URL of script that generated the exception.
     * @param {(number|string)} lineNo The line number at which the error
     * occurred.
     * @param {?(number|string)} colNo The column number at which the error
     * occurred.
     * @param {?Error} ex The actual Error object.
     */
  function traceKitWindowOnError(message, url, lineNo, colNo, ex) {
    var stack = null;

    if (lastExceptionStack) {
      TraceKit.computeStackTrace.augmentStackTraceWithInitialElement(lastExceptionStack, url, lineNo, message);
      processLastException();
    } else if (ex && utils.isError(ex)) {
      // non-string `ex` arg; attempt to extract stack trace

      // New chrome and blink send along a real error object
      // Let's just report that like a normal error.
      // See: https://mikewest.org/2013/08/debugging-runtime-errors-with-window-onerror
      stack = TraceKit.computeStackTrace(ex);
      notifyHandlers(stack, true);
    } else {
      var location = {
        url: url,
        line: lineNo,
        column: colNo
      };

      var name = undefined;
      var msg = message; // must be new var or will modify original `arguments`
      var groups;
      if ({}.toString.call(message) === '[object String]') {
        var groups = message.match(ERROR_TYPES_RE);
        if (groups) {
          name = groups[1];
          msg = groups[2];
        }
      }

      location.func = UNKNOWN_FUNCTION;

      stack = {
        name: name,
        message: msg,
        url: getLocationHref(),
        stack: [location]
      };
      notifyHandlers(stack, true);
    }

    if (_oldOnerrorHandler) {
      return _oldOnerrorHandler.apply(this, arguments);
    }

    return false;
  }

  function installGlobalHandler() {
    if (_onErrorHandlerInstalled) {
      return;
    }
    _oldOnerrorHandler = _window.onerror;
    _window.onerror = traceKitWindowOnError;
    _onErrorHandlerInstalled = true;
  }

  function uninstallGlobalHandler() {
    if (!_onErrorHandlerInstalled) {
      return;
    }
    _window.onerror = _oldOnerrorHandler;
    _onErrorHandlerInstalled = false;
    _oldOnerrorHandler = undefined;
  }

  function processLastException() {
    var _lastExceptionStack = lastExceptionStack,
        _lastArgs = lastArgs;
    lastArgs = null;
    lastExceptionStack = null;
    lastException = null;
    notifyHandlers.apply(null, [_lastExceptionStack, false].concat(_lastArgs));
  }

  /**
     * Reports an unhandled Error to TraceKit.
     * @param {Error} ex
     * @param {?boolean} rethrow If false, do not re-throw the exception.
     * Only used for window.onerror to not cause an infinite loop of
     * rethrowing.
     */
  function report(ex, rethrow) {
    var args = _slice.call(arguments, 1);
    if (lastExceptionStack) {
      if (lastException === ex) {
        return; // already caught by an inner catch block, ignore
      } else {
        processLastException();
      }
    }

    var stack = TraceKit.computeStackTrace(ex);
    lastExceptionStack = stack;
    lastException = ex;
    lastArgs = args;

    // If the stack trace is incomplete, wait for 2 seconds for
    // slow slow IE to see if onerror occurs or not before reporting
    // this exception; otherwise, we will end up with an incomplete
    // stack trace
    setTimeout(function () {
      if (lastException === ex) {
        processLastException();
      }
    }, stack.incomplete ? 2000 : 0);

    if (rethrow !== false) {
      throw ex; // re-throw to propagate to the top level (and cause window.onerror)
    }
  }

  report.subscribe = subscribe;
  report.unsubscribe = unsubscribe;
  report.uninstall = unsubscribeAll;
  return report;
}();

/**
 * TraceKit.computeStackTrace: cross-browser stack traces in JavaScript
 *
 * Syntax:
 *   s = TraceKit.computeStackTrace(exception) // consider using TraceKit.report instead (see below)
 * Returns:
 *   s.name              - exception name
 *   s.message           - exception message
 *   s.stack[i].url      - JavaScript or HTML file URL
 *   s.stack[i].func     - function name, or empty for anonymous functions (if guessing did not work)
 *   s.stack[i].args     - arguments passed to the function, if known
 *   s.stack[i].line     - line number, if known
 *   s.stack[i].column   - column number, if known
 *
 * Supports:
 *   - Firefox:  full stack trace with line numbers and unreliable column
 *               number on top frame
 *   - Opera 10: full stack trace with line and column numbers
 *   - Opera 9-: full stack trace with line numbers
 *   - Chrome:   full stack trace with line and column numbers
 *   - Safari:   line and column number for the topmost stacktrace element
 *               only
 *   - IE:       no line numbers whatsoever
 *
 * Tries to guess names of anonymous functions by looking for assignments
 * in the source code. In IE and Safari, we have to guess source file names
 * by searching for function bodies inside all page scripts. This will not
 * work for scripts that are loaded cross-domain.
 * Here be dragons: some function names may be guessed incorrectly, and
 * duplicate functions may be mismatched.
 *
 * TraceKit.computeStackTrace should only be used for tracing purposes.
 * Logging of unhandled exceptions should be done with TraceKit.report,
 * which builds on top of TraceKit.computeStackTrace and provides better
 * IE support by utilizing the window.onerror event to retrieve information
 * about the top of the stack.
 *
 * Note: In IE and Safari, no stack trace is recorded on the Error object,
 * so computeStackTrace instead walks its *own* chain of callers.
 * This means that:
 *  * in Safari, some methods may be missing from the stack trace;
 *  * in IE, the topmost function in the stack trace will always be the
 *    caller of computeStackTrace.
 *
 * This is okay for tracing (because you are likely to be calling
 * computeStackTrace from the function you want to be the topmost element
 * of the stack trace anyway), but not okay for logging unhandled
 * exceptions (because your catch block will likely be far away from the
 * inner function that actually caused the exception).
 *
 */
TraceKit.computeStackTrace = function computeStackTraceWrapper() {
  // Contents of Exception in various browsers.
  //
  // SAFARI:
  // ex.message = Can't find variable: qq
  // ex.line = 59
  // ex.sourceId = 580238192
  // ex.sourceURL = http://...
  // ex.expressionBeginOffset = 96
  // ex.expressionCaretOffset = 98
  // ex.expressionEndOffset = 98
  // ex.name = ReferenceError
  //
  // FIREFOX:
  // ex.message = qq is not defined
  // ex.fileName = http://...
  // ex.lineNumber = 59
  // ex.columnNumber = 69
  // ex.stack = ...stack trace... (see the example below)
  // ex.name = ReferenceError
  //
  // CHROME:
  // ex.message = qq is not defined
  // ex.name = ReferenceError
  // ex.type = not_defined
  // ex.arguments = ['aa']
  // ex.stack = ...stack trace...
  //
  // INTERNET EXPLORER:
  // ex.message = ...
  // ex.name = ReferenceError
  //
  // OPERA:
  // ex.message = ...message... (see the example below)
  // ex.name = ReferenceError
  // ex.opera#sourceloc = 11  (pretty much useless, duplicates the info in ex.message)
  // ex.stacktrace = n/a; see 'opera:config#UserPrefs|Exceptions Have Stacktrace'

  /**
     * Computes stack trace information from the stack property.
     * Chrome and Gecko use this property.
     * @param {Error} ex
     * @return {?Object.<string, *>} Stack trace information.
     */
  function computeStackTraceFromStackProp(ex) {
    if (typeof ex.stack === 'undefined' || !ex.stack) return;

    var chrome = /^\s*at (.*?) ?\(((?:file|https?|blob|chrome-extension|native|eval|webpack|<anonymous>|[a-z]:|\/).*?)(?::(\d+))?(?::(\d+))?\)?\s*$/i,
        gecko = /^\s*(.*?)(?:\((.*?)\))?(?:^|@)((?:file|https?|blob|chrome|webpack|resource|\[native).*?|[^@]*bundle)(?::(\d+))?(?::(\d+))?\s*$/i,
        winjs = /^\s*at (?:((?:\[object object\])?.+) )?\(?((?:file|ms-appx|https?|webpack|blob):.*?):(\d+)(?::(\d+))?\)?\s*$/i,

    // Used to additionally parse URL/line/column from eval frames
    geckoEval = /(\S+) line (\d+)(?: > eval line \d+)* > eval/i,
        chromeEval = /\((\S*)(?::(\d+))(?::(\d+))\)/,
        lines = ex.stack.split('\n'),
        stack = [],
        submatch,
        parts,
        element,
        reference = /^(.*) is undefined$/.exec(ex.message);

    for (var i = 0, j = lines.length; i < j; ++i) {
      if (parts = chrome.exec(lines[i])) {
        var isNative = parts[2] && parts[2].indexOf('native') === 0; // start of line
        var isEval = parts[2] && parts[2].indexOf('eval') === 0; // start of line
        if (isEval && (submatch = chromeEval.exec(parts[2]))) {
          // throw out eval line/column and use top-most line/column number
          parts[2] = submatch[1]; // url
          parts[3] = submatch[2]; // line
          parts[4] = submatch[3]; // column
        }
        element = {
          url: !isNative ? parts[2] : null,
          func: parts[1] || UNKNOWN_FUNCTION,
          args: isNative ? [parts[2]] : [],
          line: parts[3] ? +parts[3] : null,
          column: parts[4] ? +parts[4] : null
        };
      } else if (parts = winjs.exec(lines[i])) {
        element = {
          url: parts[2],
          func: parts[1] || UNKNOWN_FUNCTION,
          args: [],
          line: +parts[3],
          column: parts[4] ? +parts[4] : null
        };
      } else if (parts = gecko.exec(lines[i])) {
        var isEval = parts[3] && parts[3].indexOf(' > eval') > -1;
        if (isEval && (submatch = geckoEval.exec(parts[3]))) {
          // throw out eval line/column and use top-most line number
          parts[3] = submatch[1];
          parts[4] = submatch[2];
          parts[5] = null; // no column when eval
        } else if (i === 0 && !parts[5] && typeof ex.columnNumber !== 'undefined') {
          // FireFox uses this awesome columnNumber property for its top frame
          // Also note, Firefox's column number is 0-based and everything else expects 1-based,
          // so adding 1
          // NOTE: this hack doesn't work if top-most frame is eval
          stack[0].column = ex.columnNumber + 1;
        }
        element = {
          url: parts[3],
          func: parts[1] || UNKNOWN_FUNCTION,
          args: parts[2] ? parts[2].split(',') : [],
          line: parts[4] ? +parts[4] : null,
          column: parts[5] ? +parts[5] : null
        };
      } else {
        continue;
      }

      if (!element.func && element.line) {
        element.func = UNKNOWN_FUNCTION;
      }

      stack.push(element);
    }

    if (!stack.length) {
      return null;
    }

    return {
      name: ex.name,
      message: ex.message,
      url: getLocationHref(),
      stack: stack
    };
  }

  /**
     * Adds information about the first frame to incomplete stack traces.
     * Safari and IE require this to get complete data on the first frame.
     * @param {Object.<string, *>} stackInfo Stack trace information from
     * one of the compute* methods.
     * @param {string} url The URL of the script that caused an error.
     * @param {(number|string)} lineNo The line number of the script that
     * caused an error.
     * @param {string=} message The error generated by the browser, which
     * hopefully contains the name of the object that caused the error.
     * @return {boolean} Whether or not the stack information was
     * augmented.
     */
  function augmentStackTraceWithInitialElement(stackInfo, url, lineNo, message) {
    var initial = {
      url: url,
      line: lineNo
    };

    if (initial.url && initial.line) {
      stackInfo.incomplete = false;

      if (!initial.func) {
        initial.func = UNKNOWN_FUNCTION;
      }

      if (stackInfo.stack.length > 0) {
        if (stackInfo.stack[0].url === initial.url) {
          if (stackInfo.stack[0].line === initial.line) {
            return false; // already in stack trace
          } else if (!stackInfo.stack[0].line && stackInfo.stack[0].func === initial.func) {
            stackInfo.stack[0].line = initial.line;
            return false;
          }
        }
      }

      stackInfo.stack.unshift(initial);
      stackInfo.partial = true;
      return true;
    } else {
      stackInfo.incomplete = true;
    }

    return false;
  }

  /**
     * Computes stack trace information by walking the arguments.caller
     * chain at the time the exception occurred. This will cause earlier
     * frames to be missed but is the only way to get any stack trace in
     * Safari and IE. The top frame is restored by
     * {@link augmentStackTraceWithInitialElement}.
     * @param {Error} ex
     * @return {?Object.<string, *>} Stack trace information.
     */
  function computeStackTraceByWalkingCallerChain(ex, depth) {
    var functionName = /function\s+([_$a-zA-Z\xA0-\uFFFF][_$a-zA-Z0-9\xA0-\uFFFF]*)?\s*\(/i,
        stack = [],
        funcs = {},
        recursion = false,
        parts,
        item,
        source;

    for (var curr = computeStackTraceByWalkingCallerChain.caller; curr && !recursion; curr = curr.caller) {
      if (curr === computeStackTrace || curr === TraceKit.report) {
        // console.log('skipping internal function');
        continue;
      }

      item = {
        url: null,
        func: UNKNOWN_FUNCTION,
        line: null,
        column: null
      };

      if (curr.name) {
        item.func = curr.name;
      } else if (parts = functionName.exec(curr.toString())) {
        item.func = parts[1];
      }

      if (typeof item.func === 'undefined') {
        try {
          item.func = parts.input.substring(0, parts.input.indexOf('{'));
        } catch (e) {}
      }

      if (funcs['' + curr]) {
        recursion = true;
      } else {
        funcs['' + curr] = true;
      }

      stack.push(item);
    }

    if (depth) {
      // console.log('depth is ' + depth);
      // console.log('stack is ' + stack.length);
      stack.splice(0, depth);
    }

    var result = {
      name: ex.name,
      message: ex.message,
      url: getLocationHref(),
      stack: stack
    };
    augmentStackTraceWithInitialElement(result, ex.sourceURL || ex.fileName, ex.line || ex.lineNumber, ex.message || ex.description);
    return result;
  }

  /**
     * Computes a stack trace for an exception.
     * @param {Error} ex
     * @param {(string|number)=} depth
     */
  function computeStackTrace(ex, depth) {
    var stack = null;
    depth = depth == null ? 0 : +depth;

    try {
      stack = computeStackTraceFromStackProp(ex);
      if (stack) {
        return stack;
      }
    } catch (e) {
      if (TraceKit.debug) {
        throw e;
      }
    }

    try {
      stack = computeStackTraceByWalkingCallerChain(ex, depth + 1);
      if (stack) {
        return stack;
      }
    } catch (e) {
      if (TraceKit.debug) {
        throw e;
      }
    }
    return {
      name: ex.name,
      message: ex.message,
      url: getLocationHref()
    };
  }

  computeStackTrace.augmentStackTraceWithInitialElement = augmentStackTraceWithInitialElement;
  computeStackTrace.computeStackTraceFromStackProp = computeStackTraceFromStackProp;

  return computeStackTrace;
}();

module.exports = TraceKit;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"../../src/utils":11}],13:[function(require,module,exports){
'use strict';

/*
 json-stringify-safe
 Like JSON.stringify, but doesn't throw on circular references.

 Originally forked from https://github.com/isaacs/json-stringify-safe
 version 5.0.1 on 3/8/2017 and modified to handle Errors serialization
 and IE8 compatibility. Tests for this are in test/vendor.

 ISC license: https://github.com/isaacs/json-stringify-safe/blob/master/LICENSE
*/

exports = module.exports = stringify;
exports.getSerialize = serializer;

function indexOf(haystack, needle) {
  for (var i = 0; i < haystack.length; ++i) {
    if (haystack[i] === needle) return i;
  }
  return -1;
}

function stringify(obj, replacer, spaces, cycleReplacer) {
  return JSON.stringify(obj, serializer(replacer, cycleReplacer), spaces);
}

// https://github.com/ftlabs/js-abbreviate/blob/fa709e5f139e7770a71827b1893f22418097fbda/index.js#L95-L106
function stringifyError(value) {
  var err = {
    // These properties are implemented as magical getters and don't show up in for in
    stack: value.stack,
    message: value.message,
    name: value.name
  };

  for (var i in value) {
    if (Object.prototype.hasOwnProperty.call(value, i)) {
      err[i] = value[i];
    }
  }

  return err;
}

function serializer(replacer, cycleReplacer) {
  var stack = [];
  var keys = [];

  if (cycleReplacer == null) {
    cycleReplacer = function cycleReplacer(key, value) {
      if (stack[0] === value) {
        return '[Circular ~]';
      }
      return '[Circular ~.' + keys.slice(0, indexOf(stack, value)).join('.') + ']';
    };
  }

  return function (key, value) {
    if (stack.length > 0) {
      var thisPos = indexOf(stack, this);
      ~thisPos ? stack.splice(thisPos + 1) : stack.push(this);
      ~thisPos ? keys.splice(thisPos, Infinity, key) : keys.push(key);

      if (~indexOf(stack, value)) {
        value = cycleReplacer.call(this, key, value);
      }
    } else {
      stack.push(value);
    }

    return replacer == null ? value instanceof Error ? stringifyError(value) : value : replacer.call(this, key, value);
  };
}

},{}],14:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var punycode = require('punycode');
var util = require('./util');

exports.parse = urlParse;
exports.resolve = urlResolve;
exports.resolveObject = urlResolveObject;
exports.format = urlFormat;

exports.Url = Url;

function Url() {
  this.protocol = null;
  this.slashes = null;
  this.auth = null;
  this.host = null;
  this.port = null;
  this.hostname = null;
  this.hash = null;
  this.search = null;
  this.query = null;
  this.pathname = null;
  this.path = null;
  this.href = null;
}

// Reference: RFC 3986, RFC 1808, RFC 2396

// define these here so at least they only have to be
// compiled once on the first module load.
var protocolPattern = /^([a-z0-9.+-]+:)/i,
    portPattern = /:[0-9]*$/,


// Special case for a simple path URL
simplePathPattern = /^(\/\/?(?!\/)[^\?\s]*)(\?[^\s]*)?$/,


// RFC 2396: characters reserved for delimiting URLs.
// We actually just auto-escape these.
delims = ['<', '>', '"', '`', ' ', '\r', '\n', '\t'],


// RFC 2396: characters not allowed for various reasons.
unwise = ['{', '}', '|', '\\', '^', '`'].concat(delims),


// Allowed by RFCs, but cause of XSS attacks.  Always escape these.
autoEscape = ['\''].concat(unwise),

// Characters that are never ever allowed in a hostname.
// Note that any invalid chars are also handled, but these
// are the ones that are *expected* to be seen, so we fast-path
// them.
nonHostChars = ['%', '/', '?', ';', '#'].concat(autoEscape),
    hostEndingChars = ['/', '?', '#'],
    hostnameMaxLen = 255,
    hostnamePartPattern = /^[+a-z0-9A-Z_-]{0,63}$/,
    hostnamePartStart = /^([+a-z0-9A-Z_-]{0,63})(.*)$/,

// protocols that can allow "unsafe" and "unwise" chars.
unsafeProtocol = {
  'javascript': true,
  'javascript:': true
},

// protocols that never have a hostname.
hostlessProtocol = {
  'javascript': true,
  'javascript:': true
},

// protocols that always contain a // bit.
slashedProtocol = {
  'http': true,
  'https': true,
  'ftp': true,
  'gopher': true,
  'file': true,
  'http:': true,
  'https:': true,
  'ftp:': true,
  'gopher:': true,
  'file:': true
},
    querystring = require('querystring');

function urlParse(url, parseQueryString, slashesDenoteHost) {
  if (url && util.isObject(url) && url instanceof Url) return url;

  var u = new Url();
  u.parse(url, parseQueryString, slashesDenoteHost);
  return u;
}

Url.prototype.parse = function (url, parseQueryString, slashesDenoteHost) {
  if (!util.isString(url)) {
    throw new TypeError("Parameter 'url' must be a string, not " + (typeof url === 'undefined' ? 'undefined' : _typeof(url)));
  }

  // Copy chrome, IE, opera backslash-handling behavior.
  // Back slashes before the query string get converted to forward slashes
  // See: https://code.google.com/p/chromium/issues/detail?id=25916
  var queryIndex = url.indexOf('?'),
      splitter = queryIndex !== -1 && queryIndex < url.indexOf('#') ? '?' : '#',
      uSplit = url.split(splitter),
      slashRegex = /\\/g;
  uSplit[0] = uSplit[0].replace(slashRegex, '/');
  url = uSplit.join(splitter);

  var rest = url;

  // trim before proceeding.
  // This is to support parse stuff like "  http://foo.com  \n"
  rest = rest.trim();

  if (!slashesDenoteHost && url.split('#').length === 1) {
    // Try fast path regexp
    var simplePath = simplePathPattern.exec(rest);
    if (simplePath) {
      this.path = rest;
      this.href = rest;
      this.pathname = simplePath[1];
      if (simplePath[2]) {
        this.search = simplePath[2];
        if (parseQueryString) {
          this.query = querystring.parse(this.search.substr(1));
        } else {
          this.query = this.search.substr(1);
        }
      } else if (parseQueryString) {
        this.search = '';
        this.query = {};
      }
      return this;
    }
  }

  var proto = protocolPattern.exec(rest);
  if (proto) {
    proto = proto[0];
    var lowerProto = proto.toLowerCase();
    this.protocol = lowerProto;
    rest = rest.substr(proto.length);
  }

  // figure out if it's got a host
  // user@server is *always* interpreted as a hostname, and url
  // resolution will treat //foo/bar as host=foo,path=bar because that's
  // how the browser resolves relative URLs.
  if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
    var slashes = rest.substr(0, 2) === '//';
    if (slashes && !(proto && hostlessProtocol[proto])) {
      rest = rest.substr(2);
      this.slashes = true;
    }
  }

  if (!hostlessProtocol[proto] && (slashes || proto && !slashedProtocol[proto])) {

    // there's a hostname.
    // the first instance of /, ?, ;, or # ends the host.
    //
    // If there is an @ in the hostname, then non-host chars *are* allowed
    // to the left of the last @ sign, unless some host-ending character
    // comes *before* the @-sign.
    // URLs are obnoxious.
    //
    // ex:
    // http://a@b@c/ => user:a@b host:c
    // http://a@b?@c => user:a host:c path:/?@c

    // v0.12 TODO(isaacs): This is not quite how Chrome does things.
    // Review our test case against browsers more comprehensively.

    // find the first instance of any hostEndingChars
    var hostEnd = -1;
    for (var i = 0; i < hostEndingChars.length; i++) {
      var hec = rest.indexOf(hostEndingChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd)) hostEnd = hec;
    }

    // at this point, either we have an explicit point where the
    // auth portion cannot go past, or the last @ char is the decider.
    var auth, atSign;
    if (hostEnd === -1) {
      // atSign can be anywhere.
      atSign = rest.lastIndexOf('@');
    } else {
      // atSign must be in auth portion.
      // http://a@b/c@d => host:b auth:a path:/c@d
      atSign = rest.lastIndexOf('@', hostEnd);
    }

    // Now we have a portion which is definitely the auth.
    // Pull that off.
    if (atSign !== -1) {
      auth = rest.slice(0, atSign);
      rest = rest.slice(atSign + 1);
      this.auth = decodeURIComponent(auth);
    }

    // the host is the remaining to the left of the first non-host char
    hostEnd = -1;
    for (var i = 0; i < nonHostChars.length; i++) {
      var hec = rest.indexOf(nonHostChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd)) hostEnd = hec;
    }
    // if we still have not hit it, then the entire thing is a host.
    if (hostEnd === -1) hostEnd = rest.length;

    this.host = rest.slice(0, hostEnd);
    rest = rest.slice(hostEnd);

    // pull out port.
    this.parseHost();

    // we've indicated that there is a hostname,
    // so even if it's empty, it has to be present.
    this.hostname = this.hostname || '';

    // if hostname begins with [ and ends with ]
    // assume that it's an IPv6 address.
    var ipv6Hostname = this.hostname[0] === '[' && this.hostname[this.hostname.length - 1] === ']';

    // validate a little.
    if (!ipv6Hostname) {
      var hostparts = this.hostname.split(/\./);
      for (var i = 0, l = hostparts.length; i < l; i++) {
        var part = hostparts[i];
        if (!part) continue;
        if (!part.match(hostnamePartPattern)) {
          var newpart = '';
          for (var j = 0, k = part.length; j < k; j++) {
            if (part.charCodeAt(j) > 127) {
              // we replace non-ASCII char with a temporary placeholder
              // we need this to make sure size of hostname is not
              // broken by replacing non-ASCII by nothing
              newpart += 'x';
            } else {
              newpart += part[j];
            }
          }
          // we test again with ASCII char only
          if (!newpart.match(hostnamePartPattern)) {
            var validParts = hostparts.slice(0, i);
            var notHost = hostparts.slice(i + 1);
            var bit = part.match(hostnamePartStart);
            if (bit) {
              validParts.push(bit[1]);
              notHost.unshift(bit[2]);
            }
            if (notHost.length) {
              rest = '/' + notHost.join('.') + rest;
            }
            this.hostname = validParts.join('.');
            break;
          }
        }
      }
    }

    if (this.hostname.length > hostnameMaxLen) {
      this.hostname = '';
    } else {
      // hostnames are always lower case.
      this.hostname = this.hostname.toLowerCase();
    }

    if (!ipv6Hostname) {
      // IDNA Support: Returns a punycoded representation of "domain".
      // It only converts parts of the domain name that
      // have non-ASCII characters, i.e. it doesn't matter if
      // you call it with a domain that already is ASCII-only.
      this.hostname = punycode.toASCII(this.hostname);
    }

    var p = this.port ? ':' + this.port : '';
    var h = this.hostname || '';
    this.host = h + p;
    this.href += this.host;

    // strip [ and ] from the hostname
    // the host field still retains them, though
    if (ipv6Hostname) {
      this.hostname = this.hostname.substr(1, this.hostname.length - 2);
      if (rest[0] !== '/') {
        rest = '/' + rest;
      }
    }
  }

  // now rest is set to the post-host stuff.
  // chop off any delim chars.
  if (!unsafeProtocol[lowerProto]) {

    // First, make 100% sure that any "autoEscape" chars get
    // escaped, even if encodeURIComponent doesn't think they
    // need to be.
    for (var i = 0, l = autoEscape.length; i < l; i++) {
      var ae = autoEscape[i];
      if (rest.indexOf(ae) === -1) continue;
      var esc = encodeURIComponent(ae);
      if (esc === ae) {
        esc = escape(ae);
      }
      rest = rest.split(ae).join(esc);
    }
  }

  // chop off from the tail first.
  var hash = rest.indexOf('#');
  if (hash !== -1) {
    // got a fragment string.
    this.hash = rest.substr(hash);
    rest = rest.slice(0, hash);
  }
  var qm = rest.indexOf('?');
  if (qm !== -1) {
    this.search = rest.substr(qm);
    this.query = rest.substr(qm + 1);
    if (parseQueryString) {
      this.query = querystring.parse(this.query);
    }
    rest = rest.slice(0, qm);
  } else if (parseQueryString) {
    // no query string, but parseQueryString still requested
    this.search = '';
    this.query = {};
  }
  if (rest) this.pathname = rest;
  if (slashedProtocol[lowerProto] && this.hostname && !this.pathname) {
    this.pathname = '/';
  }

  //to support http.request
  if (this.pathname || this.search) {
    var p = this.pathname || '';
    var s = this.search || '';
    this.path = p + s;
  }

  // finally, reconstruct the href based on what has been validated.
  this.href = this.format();
  return this;
};

// format a parsed object into a url string
function urlFormat(obj) {
  // ensure it's an object, and not a string url.
  // If it's an obj, this is a no-op.
  // this way, you can call url_format() on strings
  // to clean up potentially wonky urls.
  if (util.isString(obj)) obj = urlParse(obj);
  if (!(obj instanceof Url)) return Url.prototype.format.call(obj);
  return obj.format();
}

Url.prototype.format = function () {
  var auth = this.auth || '';
  if (auth) {
    auth = encodeURIComponent(auth);
    auth = auth.replace(/%3A/i, ':');
    auth += '@';
  }

  var protocol = this.protocol || '',
      pathname = this.pathname || '',
      hash = this.hash || '',
      host = false,
      query = '';

  if (this.host) {
    host = auth + this.host;
  } else if (this.hostname) {
    host = auth + (this.hostname.indexOf(':') === -1 ? this.hostname : '[' + this.hostname + ']');
    if (this.port) {
      host += ':' + this.port;
    }
  }

  if (this.query && util.isObject(this.query) && Object.keys(this.query).length) {
    query = querystring.stringify(this.query);
  }

  var search = this.search || query && '?' + query || '';

  if (protocol && protocol.substr(-1) !== ':') protocol += ':';

  // only the slashedProtocols get the //.  Not mailto:, xmpp:, etc.
  // unless they had them to begin with.
  if (this.slashes || (!protocol || slashedProtocol[protocol]) && host !== false) {
    host = '//' + (host || '');
    if (pathname && pathname.charAt(0) !== '/') pathname = '/' + pathname;
  } else if (!host) {
    host = '';
  }

  if (hash && hash.charAt(0) !== '#') hash = '#' + hash;
  if (search && search.charAt(0) !== '?') search = '?' + search;

  pathname = pathname.replace(/[?#]/g, function (match) {
    return encodeURIComponent(match);
  });
  search = search.replace('#', '%23');

  return protocol + host + pathname + search + hash;
};

function urlResolve(source, relative) {
  return urlParse(source, false, true).resolve(relative);
}

Url.prototype.resolve = function (relative) {
  return this.resolveObject(urlParse(relative, false, true)).format();
};

function urlResolveObject(source, relative) {
  if (!source) return relative;
  return urlParse(source, false, true).resolveObject(relative);
}

Url.prototype.resolveObject = function (relative) {
  if (util.isString(relative)) {
    var rel = new Url();
    rel.parse(relative, false, true);
    relative = rel;
  }

  var result = new Url();
  var tkeys = Object.keys(this);
  for (var tk = 0; tk < tkeys.length; tk++) {
    var tkey = tkeys[tk];
    result[tkey] = this[tkey];
  }

  // hash is always overridden, no matter what.
  // even href="" will remove it.
  result.hash = relative.hash;

  // if the relative url is empty, then there's nothing left to do here.
  if (relative.href === '') {
    result.href = result.format();
    return result;
  }

  // hrefs like //foo/bar always cut to the protocol.
  if (relative.slashes && !relative.protocol) {
    // take everything except the protocol from relative
    var rkeys = Object.keys(relative);
    for (var rk = 0; rk < rkeys.length; rk++) {
      var rkey = rkeys[rk];
      if (rkey !== 'protocol') result[rkey] = relative[rkey];
    }

    //urlParse appends trailing / to urls like http://www.example.com
    if (slashedProtocol[result.protocol] && result.hostname && !result.pathname) {
      result.path = result.pathname = '/';
    }

    result.href = result.format();
    return result;
  }

  if (relative.protocol && relative.protocol !== result.protocol) {
    // if it's a known url protocol, then changing
    // the protocol does weird things
    // first, if it's not file:, then we MUST have a host,
    // and if there was a path
    // to begin with, then we MUST have a path.
    // if it is file:, then the host is dropped,
    // because that's known to be hostless.
    // anything else is assumed to be absolute.
    if (!slashedProtocol[relative.protocol]) {
      var keys = Object.keys(relative);
      for (var v = 0; v < keys.length; v++) {
        var k = keys[v];
        result[k] = relative[k];
      }
      result.href = result.format();
      return result;
    }

    result.protocol = relative.protocol;
    if (!relative.host && !hostlessProtocol[relative.protocol]) {
      var relPath = (relative.pathname || '').split('/');
      while (relPath.length && !(relative.host = relPath.shift())) {}
      if (!relative.host) relative.host = '';
      if (!relative.hostname) relative.hostname = '';
      if (relPath[0] !== '') relPath.unshift('');
      if (relPath.length < 2) relPath.unshift('');
      result.pathname = relPath.join('/');
    } else {
      result.pathname = relative.pathname;
    }
    result.search = relative.search;
    result.query = relative.query;
    result.host = relative.host || '';
    result.auth = relative.auth;
    result.hostname = relative.hostname || relative.host;
    result.port = relative.port;
    // to support http.request
    if (result.pathname || result.search) {
      var p = result.pathname || '';
      var s = result.search || '';
      result.path = p + s;
    }
    result.slashes = result.slashes || relative.slashes;
    result.href = result.format();
    return result;
  }

  var isSourceAbs = result.pathname && result.pathname.charAt(0) === '/',
      isRelAbs = relative.host || relative.pathname && relative.pathname.charAt(0) === '/',
      mustEndAbs = isRelAbs || isSourceAbs || result.host && relative.pathname,
      removeAllDots = mustEndAbs,
      srcPath = result.pathname && result.pathname.split('/') || [],
      relPath = relative.pathname && relative.pathname.split('/') || [],
      psychotic = result.protocol && !slashedProtocol[result.protocol];

  // if the url is a non-slashed url, then relative
  // links like ../.. should be able
  // to crawl up to the hostname, as well.  This is strange.
  // result.protocol has already been set by now.
  // Later on, put the first path part into the host field.
  if (psychotic) {
    result.hostname = '';
    result.port = null;
    if (result.host) {
      if (srcPath[0] === '') srcPath[0] = result.host;else srcPath.unshift(result.host);
    }
    result.host = '';
    if (relative.protocol) {
      relative.hostname = null;
      relative.port = null;
      if (relative.host) {
        if (relPath[0] === '') relPath[0] = relative.host;else relPath.unshift(relative.host);
      }
      relative.host = null;
    }
    mustEndAbs = mustEndAbs && (relPath[0] === '' || srcPath[0] === '');
  }

  if (isRelAbs) {
    // it's absolute.
    result.host = relative.host || relative.host === '' ? relative.host : result.host;
    result.hostname = relative.hostname || relative.hostname === '' ? relative.hostname : result.hostname;
    result.search = relative.search;
    result.query = relative.query;
    srcPath = relPath;
    // fall through to the dot-handling below.
  } else if (relPath.length) {
    // it's relative
    // throw away the existing file, and take the new path instead.
    if (!srcPath) srcPath = [];
    srcPath.pop();
    srcPath = srcPath.concat(relPath);
    result.search = relative.search;
    result.query = relative.query;
  } else if (!util.isNullOrUndefined(relative.search)) {
    // just pull out the search.
    // like href='?foo'.
    // Put this after the other two cases because it simplifies the booleans
    if (psychotic) {
      result.hostname = result.host = srcPath.shift();
      //occationaly the auth can get stuck only in host
      //this especially happens in cases like
      //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
      var authInHost = result.host && result.host.indexOf('@') > 0 ? result.host.split('@') : false;
      if (authInHost) {
        result.auth = authInHost.shift();
        result.host = result.hostname = authInHost.shift();
      }
    }
    result.search = relative.search;
    result.query = relative.query;
    //to support http.request
    if (!util.isNull(result.pathname) || !util.isNull(result.search)) {
      result.path = (result.pathname ? result.pathname : '') + (result.search ? result.search : '');
    }
    result.href = result.format();
    return result;
  }

  if (!srcPath.length) {
    // no path at all.  easy.
    // we've already handled the other stuff above.
    result.pathname = null;
    //to support http.request
    if (result.search) {
      result.path = '/' + result.search;
    } else {
      result.path = null;
    }
    result.href = result.format();
    return result;
  }

  // if a url ENDs in . or .., then it must get a trailing slash.
  // however, if it ends in anything else non-slashy,
  // then it must NOT get a trailing slash.
  var last = srcPath.slice(-1)[0];
  var hasTrailingSlash = (result.host || relative.host || srcPath.length > 1) && (last === '.' || last === '..') || last === '';

  // strip single dots, resolve double dots to parent dir
  // if the path tries to go above the root, `up` ends up > 0
  var up = 0;
  for (var i = srcPath.length; i >= 0; i--) {
    last = srcPath[i];
    if (last === '.') {
      srcPath.splice(i, 1);
    } else if (last === '..') {
      srcPath.splice(i, 1);
      up++;
    } else if (up) {
      srcPath.splice(i, 1);
      up--;
    }
  }

  // if the path is allowed to go above the root, restore leading ..s
  if (!mustEndAbs && !removeAllDots) {
    for (; up--; up) {
      srcPath.unshift('..');
    }
  }

  if (mustEndAbs && srcPath[0] !== '' && (!srcPath[0] || srcPath[0].charAt(0) !== '/')) {
    srcPath.unshift('');
  }

  if (hasTrailingSlash && srcPath.join('/').substr(-1) !== '/') {
    srcPath.push('');
  }

  var isAbsolute = srcPath[0] === '' || srcPath[0] && srcPath[0].charAt(0) === '/';

  // put the host back
  if (psychotic) {
    result.hostname = result.host = isAbsolute ? '' : srcPath.length ? srcPath.shift() : '';
    //occationaly the auth can get stuck only in host
    //this especially happens in cases like
    //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
    var authInHost = result.host && result.host.indexOf('@') > 0 ? result.host.split('@') : false;
    if (authInHost) {
      result.auth = authInHost.shift();
      result.host = result.hostname = authInHost.shift();
    }
  }

  mustEndAbs = mustEndAbs || result.host && srcPath.length;

  if (mustEndAbs && !isAbsolute) {
    srcPath.unshift('');
  }

  if (!srcPath.length) {
    result.pathname = null;
    result.path = null;
  } else {
    result.pathname = srcPath.join('/');
  }

  //to support request.http
  if (!util.isNull(result.pathname) || !util.isNull(result.search)) {
    result.path = (result.pathname ? result.pathname : '') + (result.search ? result.search : '');
  }
  result.auth = relative.auth || result.auth;
  result.slashes = result.slashes || relative.slashes;
  result.href = result.format();
  return result;
};

Url.prototype.parseHost = function () {
  var host = this.host;
  var port = portPattern.exec(host);
  if (port) {
    port = port[0];
    if (port !== ':') {
      this.port = port.substr(1);
    }
    host = host.substr(0, host.length - port.length);
  }
  if (host) this.hostname = host;
};

},{"./util":15,"punycode":3,"querystring":6}],15:[function(require,module,exports){
'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

module.exports = {
  isString: function isString(arg) {
    return typeof arg === 'string';
  },
  isObject: function isObject(arg) {
    return (typeof arg === 'undefined' ? 'undefined' : _typeof(arg)) === 'object' && arg !== null;
  },
  isNull: function isNull(arg) {
    return arg === null;
  },
  isNullOrUndefined: function isNullOrUndefined(arg) {
    return arg == null;
  }
};

},{}],16:[function(require,module,exports){
'use strict';

var v1 = require('./v1');
var v4 = require('./v4');

var uuid = v4;
uuid.v1 = v1;
uuid.v4 = v4;

module.exports = uuid;

},{"./v1":19,"./v4":20}],17:[function(require,module,exports){
'use strict';

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
var byteToHex = [];
for (var i = 0; i < 256; ++i) {
  byteToHex[i] = (i + 0x100).toString(16).substr(1);
}

function bytesToUuid(buf, offset) {
  var i = offset || 0;
  var bth = byteToHex;
  return bth[buf[i++]] + bth[buf[i++]] + bth[buf[i++]] + bth[buf[i++]] + '-' + bth[buf[i++]] + bth[buf[i++]] + '-' + bth[buf[i++]] + bth[buf[i++]] + '-' + bth[buf[i++]] + bth[buf[i++]] + '-' + bth[buf[i++]] + bth[buf[i++]] + bth[buf[i++]] + bth[buf[i++]] + bth[buf[i++]] + bth[buf[i++]];
}

module.exports = bytesToUuid;

},{}],18:[function(require,module,exports){
(function (global){
"use strict";

// Unique ID creation requires a high quality random # generator.  In the
// browser this is a little complicated due to unknown quality of Math.random()
// and inconsistent support for the `crypto` API.  We do the best we can via
// feature-detection
var rng;

var crypto = global.crypto || global.msCrypto; // for IE 11
if (crypto && crypto.getRandomValues) {
  // WHATWG crypto RNG - http://wiki.whatwg.org/wiki/Crypto
  var rnds8 = new Uint8Array(16); // eslint-disable-line no-undef
  rng = function whatwgRNG() {
    crypto.getRandomValues(rnds8);
    return rnds8;
  };
}

if (!rng) {
  // Math.random()-based (RNG)
  //
  // If all else fails, use Math.random().  It's fast, but is of unspecified
  // quality.
  var rnds = new Array(16);
  rng = function rng() {
    for (var i = 0, r; i < 16; i++) {
      if ((i & 0x03) === 0) r = Math.random() * 0x100000000;
      rnds[i] = r >>> ((i & 0x03) << 3) & 0xff;
    }

    return rnds;
  };
}

module.exports = rng;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],19:[function(require,module,exports){
'use strict';

var rng = require('./lib/rng');
var bytesToUuid = require('./lib/bytesToUuid');

// **`v1()` - Generate time-based UUID**
//
// Inspired by https://github.com/LiosK/UUID.js
// and http://docs.python.org/library/uuid.html

// random #'s we need to init node and clockseq
var _seedBytes = rng();

// Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
var _nodeId = [_seedBytes[0] | 0x01, _seedBytes[1], _seedBytes[2], _seedBytes[3], _seedBytes[4], _seedBytes[5]];

// Per 4.2.2, randomize (14 bit) clockseq
var _clockseq = (_seedBytes[6] << 8 | _seedBytes[7]) & 0x3fff;

// Previous uuid creation time
var _lastMSecs = 0,
    _lastNSecs = 0;

// See https://github.com/broofa/node-uuid for API details
function v1(options, buf, offset) {
  var i = buf && offset || 0;
  var b = buf || [];

  options = options || {};

  var clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq;

  // UUID timestamps are 100 nano-second units since the Gregorian epoch,
  // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
  // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
  // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.
  var msecs = options.msecs !== undefined ? options.msecs : new Date().getTime();

  // Per 4.2.1.2, use count of uuid's generated during the current clock
  // cycle to simulate higher resolution clock
  var nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1;

  // Time since last uuid creation (in msecs)
  var dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000;

  // Per 4.2.1.2, Bump clockseq on clock regression
  if (dt < 0 && options.clockseq === undefined) {
    clockseq = clockseq + 1 & 0x3fff;
  }

  // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
  // time interval
  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
    nsecs = 0;
  }

  // Per 4.2.1.2 Throw error if too many uuids are requested
  if (nsecs >= 10000) {
    throw new Error('uuid.v1(): Can\'t create more than 10M uuids/sec');
  }

  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq;

  // Per 4.1.4 - Convert from unix epoch to Gregorian epoch
  msecs += 12219292800000;

  // `time_low`
  var tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
  b[i++] = tl >>> 24 & 0xff;
  b[i++] = tl >>> 16 & 0xff;
  b[i++] = tl >>> 8 & 0xff;
  b[i++] = tl & 0xff;

  // `time_mid`
  var tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
  b[i++] = tmh >>> 8 & 0xff;
  b[i++] = tmh & 0xff;

  // `time_high_and_version`
  b[i++] = tmh >>> 24 & 0xf | 0x10; // include version
  b[i++] = tmh >>> 16 & 0xff;

  // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)
  b[i++] = clockseq >>> 8 | 0x80;

  // `clock_seq_low`
  b[i++] = clockseq & 0xff;

  // `node`
  var node = options.node || _nodeId;
  for (var n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }

  return buf ? buf : bytesToUuid(b);
}

module.exports = v1;

},{"./lib/bytesToUuid":17,"./lib/rng":18}],20:[function(require,module,exports){
'use strict';

var rng = require('./lib/rng');
var bytesToUuid = require('./lib/bytesToUuid');

function v4(options, buf, offset) {
  var i = buf && offset || 0;

  if (typeof options == 'string') {
    buf = options == 'binary' ? new Array(16) : null;
    options = null;
  }
  options = options || {};

  var rnds = options.random || (options.rng || rng)();

  // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`
  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80;

  // Copy bytes to buffer, if provided
  if (buf) {
    for (var ii = 0; ii < 16; ++ii) {
      buf[i + ii] = rnds[ii];
    }
  }

  return buf || bytesToUuid(rnds);
}

module.exports = v4;

},{"./lib/bytesToUuid":17,"./lib/rng":18}],21:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __read = undefined && undefined.__read || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o),
        r,
        ar = [],
        e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) {
            ar.push(r.value);
        }
    } catch (error) {
        e = { error: error };
    } finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        } finally {
            if (e) throw e.error;
        }
    }
    return ar;
};
var __spread = undefined && undefined.__spread || function () {
    for (var ar = [], i = 0; i < arguments.length; i++) {
        ar = ar.concat(__read(arguments[i]));
    }return ar;
};
var __values = undefined && undefined.__values || function (o) {
    var m = typeof Symbol === "function" && o[Symbol.iterator],
        i = 0;
    if (m) return m.call(o);
    return {
        next: function next() {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
};
Object.defineProperty(exports, "__esModule", { value: true });
var shadowsocks_config_1 = require("ShadowsocksConfig/shadowsocks_config");
var errors = require("../model/errors");
var events = require("../model/events");
var settings_1 = require("./settings");
// If s is a URL whose fragment contains a Shadowsocks URL then return that Shadowsocks URL,
// otherwise return s.
function unwrapInvite(s) {
    try {
        var url = new URL(s);
        if (url.hash) {
            var decodedFragment = decodeURIComponent(url.hash);
            // Search in the fragment for ss:// for two reasons:
            //  - URL.hash includes the leading # (what).
            //  - When a user opens invite.html#ENCODEDSSURL in their browser, the website (currently)
            //    redirects to invite.html#/en/invite/ENCODEDSSURL. Since copying that redirected URL
            //    seems like a reasonable thing to do, let's support those URLs too.
            var possibleShadowsocksUrl = decodedFragment.substring(decodedFragment.indexOf('ss://'));
            if (new URL(possibleShadowsocksUrl).protocol === 'ss:') {
                return possibleShadowsocksUrl;
            }
        }
    } catch (e) {
        // Something wasn't a URL, or it couldn't be decoded - no problem, people put all kinds of
        // crazy things in the clipboard.
    }
    return s;
}
exports.unwrapInvite = unwrapInvite;
var App = /** @class */function () {
    function App(eventQueue, serverRepo, rootEl, debugMode, urlInterceptor, clipboard, errorReporter, settings, environmentVars, updater, quitApplication, document) {
        if (document === void 0) {
            document = window.document;
        }
        this.eventQueue = eventQueue;
        this.serverRepo = serverRepo;
        this.rootEl = rootEl;
        this.debugMode = debugMode;
        this.clipboard = clipboard;
        this.errorReporter = errorReporter;
        this.settings = settings;
        this.environmentVars = environmentVars;
        this.updater = updater;
        this.quitApplication = quitApplication;
        this.ignoredAccessKeys = {};
        this.serverListEl = rootEl.$.serversView.$.serverList;
        this.feedbackViewEl = rootEl.$.feedbackView;
        this.syncServersToUI();
        this.syncConnectivityStateToServerCards();
        rootEl.$.aboutView.version = environmentVars.APP_VERSION;
        this.localize = this.rootEl.localize.bind(this.rootEl);
        if (urlInterceptor) {
            this.registerUrlInterceptionListener(urlInterceptor);
        } else {
            console.warn('no urlInterceptor, ss:// urls will not be intercepted');
        }
        this.clipboard.setListener(this.handleClipboardText.bind(this));
        this.updater.setListener(this.updateDownloaded.bind(this));
        // Register Cordova mobile foreground event to sync server connectivity.
        document.addEventListener('resume', this.syncConnectivityStateToServerCards.bind(this));
        // Register handlers for events fired by Polymer components.
        this.rootEl.addEventListener('PromptAddServerRequested', this.requestPromptAddServer.bind(this));
        this.rootEl.addEventListener('AddServerConfirmationRequested', this.requestAddServerConfirmation.bind(this));
        this.rootEl.addEventListener('AddServerRequested', this.requestAddServer.bind(this));
        this.rootEl.addEventListener('IgnoreServerRequested', this.requestIgnoreServer.bind(this));
        this.rootEl.addEventListener('ConnectPressed', this.connectServer.bind(this));
        this.rootEl.addEventListener('DisconnectPressed', this.disconnectServer.bind(this));
        this.rootEl.addEventListener('ForgetPressed', this.forgetServer.bind(this));
        this.rootEl.addEventListener('RenameRequested', this.renameServer.bind(this));
        this.rootEl.addEventListener('QuitPressed', this.quitApplication.bind(this));
        this.rootEl.addEventListener('AutoConnectDialogDismissed', this.autoConnectDialogDismissed.bind(this));
        this.rootEl.addEventListener('ShowServerRename', this.rootEl.showServerRename.bind(this.rootEl));
        this.feedbackViewEl.$.submitButton.addEventListener('tap', this.submitFeedback.bind(this));
        this.rootEl.addEventListener('PrivacyTermsAcked', this.ackPrivacyTerms.bind(this));
        // Register handlers for events published to our event queue.
        this.eventQueue.subscribe(events.ServerAdded, this.showServerAdded.bind(this));
        this.eventQueue.subscribe(events.ServerForgotten, this.showServerForgotten.bind(this));
        this.eventQueue.subscribe(events.ServerRenamed, this.showServerRenamed.bind(this));
        this.eventQueue.subscribe(events.ServerForgetUndone, this.showServerForgetUndone.bind(this));
        this.eventQueue.subscribe(events.ServerConnected, this.showServerConnected.bind(this));
        this.eventQueue.subscribe(events.ServerDisconnected, this.showServerDisconnected.bind(this));
        this.eventQueue.subscribe(events.ServerReconnecting, this.showServerReconnecting.bind(this));
        this.eventQueue.startPublishing();
        if (!this.arePrivacyTermsAcked()) {
            this.displayPrivacyView();
        }
        this.displayZeroStateUi();
        this.pullClipboardText();
    }
    App.prototype.showLocalizedError = function (e, toastDuration) {
        var _this = this;
        if (toastDuration === void 0) {
            toastDuration = 10000;
        }
        var messageKey;
        var messageParams;
        var buttonKey;
        var buttonHandler;
        var buttonLink;
        if (e instanceof errors.VpnPermissionNotGranted) {
            messageKey = 'outline-plugin-error-vpn-permission-not-granted';
        } else if (e instanceof errors.InvalidServerCredentials) {
            messageKey = 'outline-plugin-error-invalid-server-credentials';
        } else if (e instanceof errors.RemoteUdpForwardingDisabled) {
            messageKey = 'outline-plugin-error-udp-forwarding-not-enabled';
        } else if (e instanceof errors.ServerUnreachable) {
            messageKey = 'outline-plugin-error-server-unreachable';
        } else if (e instanceof errors.FeedbackSubmissionError) {
            messageKey = 'error-feedback-submission';
        } else if (e instanceof errors.ServerUrlInvalid) {
            messageKey = 'error-invalid-access-key';
        } else if (e instanceof errors.ServerIncompatible) {
            messageKey = 'error-server-incompatible';
        } else if (e instanceof errors.OperationTimedOut) {
            messageKey = 'error-timeout';
        } else if (e instanceof errors.ShadowsocksStartFailure && this.isWindows()) {
            // Fall through to `error-unexpected` for other platforms.
            messageKey = 'outline-plugin-error-antivirus';
            buttonKey = 'fix-this';
            buttonLink = 'https://s3.amazonaws.com/outline-vpn/index.html#/en/support/antivirusBlock';
        } else if (e instanceof errors.ConfigureSystemProxyFailure) {
            messageKey = 'outline-plugin-error-routing-tables';
            buttonKey = 'feedback-page-title';
            buttonHandler = function buttonHandler() {
                // TODO: Drop-down has no selected item, why not?
                _this.rootEl.changePage('feedback');
            };
        } else if (e instanceof errors.NoAdminPermissions) {
            messageKey = 'outline-plugin-error-admin-permissions';
        } else if (e instanceof errors.UnsupportedRoutingTable) {
            messageKey = 'outline-plugin-error-unsupported-routing-table';
        } else if (e instanceof errors.ServerAlreadyAdded) {
            messageKey = 'error-server-already-added';
            messageParams = ['serverName', e.server.name];
        } else if (e instanceof errors.SystemConfigurationException) {
            messageKey = 'outline-plugin-error-system-configuration';
        } else {
            messageKey = 'error-unexpected';
        }
        var message = messageParams ? this.localize.apply(this, __spread([messageKey], messageParams)) : this.localize(messageKey);
        // Defer by 500ms so that this toast is shown after any toasts that get shown when any
        // currently-in-flight domain events land (e.g. fake servers added).
        if (this.rootEl && this.rootEl.async) {
            this.rootEl.async(function () {
                _this.rootEl.showToast(message, toastDuration, buttonKey ? _this.localize(buttonKey) : undefined, buttonHandler, buttonLink);
            }, 500);
        }
    };
    App.prototype.pullClipboardText = function () {
        var _this = this;
        this.clipboard.getContents().then(function (text) {
            _this.handleClipboardText(text);
        }, function (e) {
            console.warn('cannot read clipboard, system may lack clipboard support');
        });
    };
    App.prototype.showServerConnected = function (event) {
        console.debug("server " + event.server.id + " connected");
        var card = this.serverListEl.getServerCard(event.server.id);
        card.state = 'CONNECTED';
    };
    App.prototype.showServerDisconnected = function (event) {
        console.debug("server " + event.server.id + " disconnected");
        try {
            this.serverListEl.getServerCard(event.server.id).state = 'DISCONNECTED';
        } catch (e) {
            console.warn('server card not found after disconnection event, assuming forgotten');
        }
    };
    App.prototype.showServerReconnecting = function (event) {
        console.debug("server " + event.server.id + " reconnecting");
        var card = this.serverListEl.getServerCard(event.server.id);
        card.state = 'RECONNECTING';
    };
    App.prototype.displayZeroStateUi = function () {
        if (this.rootEl.$.serversView.shouldShowZeroState) {
            this.rootEl.$.addServerView.openAddServerSheet();
        }
    };
    App.prototype.arePrivacyTermsAcked = function () {
        try {
            return this.settings.get(settings_1.SettingsKey.PRIVACY_ACK) === 'true';
        } catch (e) {
            console.error("could not read privacy acknowledgement setting, assuming not acknowledged");
        }
        return false;
    };
    App.prototype.displayPrivacyView = function () {
        this.rootEl.$.serversView.hidden = true;
        this.rootEl.$.privacyView.hidden = false;
    };
    App.prototype.ackPrivacyTerms = function () {
        this.rootEl.$.serversView.hidden = false;
        this.rootEl.$.privacyView.hidden = true;
        this.settings.set(settings_1.SettingsKey.PRIVACY_ACK, 'true');
    };
    App.prototype.handleClipboardText = function (text) {
        // Shorten, sanitise.
        // Note that we always check the text, even if the contents are same as last time, because we
        // keep an in-memory cache of user-ignored access keys.
        text = text.substring(0, 1000).trim();
        try {
            this.confirmAddServer(text, true);
        } catch (err) {
            // Don't alert the user; high false positive rate.
        }
    };
    App.prototype.updateDownloaded = function () {
        this.rootEl.showToast(this.localize('update-downloaded'), 60000);
    };
    App.prototype.requestPromptAddServer = function () {
        this.rootEl.promptAddServer();
    };
    // Caches an ignored server access key so we don't prompt the user to add it again.
    App.prototype.requestIgnoreServer = function (event) {
        var accessKey = event.detail.accessKey;
        this.ignoredAccessKeys[accessKey] = true;
    };
    App.prototype.requestAddServer = function (event) {
        try {
            this.serverRepo.add(event.detail.serverConfig);
        } catch (err) {
            this.changeToDefaultPage();
            this.showLocalizedError(err);
        }
    };
    App.prototype.requestAddServerConfirmation = function (event) {
        var accessKey = event.detail.accessKey;
        console.debug('Got add server confirmation request from UI');
        try {
            this.confirmAddServer(accessKey);
        } catch (err) {
            console.error('Failed to confirm add sever.', err);
            var addServerView = this.rootEl.$.addServerView;
            addServerView.$.accessKeyInput.invalid = true;
        }
    };
    App.prototype.confirmAddServer = function (accessKey, fromClipboard) {
        if (fromClipboard === void 0) {
            fromClipboard = false;
        }
        var addServerView = this.rootEl.$.addServerView;
        accessKey = unwrapInvite(accessKey);
        if (fromClipboard && accessKey in this.ignoredAccessKeys) {
            return console.debug('Ignoring access key');
        } else if (fromClipboard && addServerView.isAddingServer()) {
            return console.debug('Already adding a server');
        }
        // Expect SHADOWSOCKS_URI.parse to throw on invalid access key; propagate any exception.
        var shadowsocksConfig = null;
        try {
            shadowsocksConfig = shadowsocks_config_1.SHADOWSOCKS_URI.parse(accessKey);
        } catch (error) {
            var message = !!error.message ? error.message : 'Failed to parse access key';
            throw new errors.ServerUrlInvalid(message);
        }
        if (shadowsocksConfig.host.isIPv6) {
            throw new errors.ServerIncompatible('Only IPv4 addresses are currently supported');
        }
        var name = shadowsocksConfig.extra.outline ? this.localize('server-default-name-outline') : shadowsocksConfig.tag.data ? shadowsocksConfig.tag.data : this.localize('server-default-name');
        var serverConfig = {
            host: shadowsocksConfig.host.data,
            port: shadowsocksConfig.port.data,
            method: shadowsocksConfig.method.data,
            password: shadowsocksConfig.password.data,
            name: name
        };
        if (!this.serverRepo.containsServer(serverConfig)) {
            // Only prompt the user to add new servers.
            try {
                addServerView.openAddServerConfirmationSheet(accessKey, serverConfig);
            } catch (err) {
                console.error('Failed to open add sever confirmation sheet:', err.message);
                if (!fromClipboard) this.showLocalizedError();
            }
        } else if (!fromClipboard) {
            // Display error message if this is not a clipboard add.
            addServerView.close();
            this.showLocalizedError(new errors.ServerAlreadyAdded(this.serverRepo.createServer('', serverConfig, this.eventQueue)));
        }
    };
    App.prototype.forgetServer = function (event) {
        var _this = this;
        var serverId = event.detail.serverId;
        var server = this.serverRepo.getById(serverId);
        if (!server) {
            console.error("No server with id " + serverId);
            return this.showLocalizedError();
        }
        var onceNotRunning = server.checkRunning().then(function (isRunning) {
            return isRunning ? _this.disconnectServer(event) : Promise.resolve();
        });
        onceNotRunning.then(function () {
            _this.serverRepo.forget(serverId);
        });
    };
    App.prototype.renameServer = function (event) {
        var serverId = event.detail.serverId;
        var newName = event.detail.newName;
        this.serverRepo.rename(serverId, newName);
    };
    App.prototype.connectServer = function (event) {
        var _this = this;
        var serverId = event.detail.serverId;
        if (!serverId) {
            throw new Error("connectServer event had no server ID");
        }
        var server = this.getServerByServerId(serverId);
        var card = this.getCardByServerId(serverId);
        console.log("connecting to server " + serverId);
        card.state = 'CONNECTING';
        server.connect().then(function () {
            card.state = 'CONNECTED';
            console.log("connected to server " + serverId);
            _this.rootEl.showToast(_this.localize('server-connected', 'serverName', server.name));
            _this.maybeShowAutoConnectDialog();
        }, function (e) {
            card.state = 'DISCONNECTED';
            _this.showLocalizedError(e);
            console.error("could not connect to server " + serverId + ": " + e.name);
            if (!(e instanceof errors.RegularNativeError)) {
                _this.errorReporter.report("connection failure: " + e.name, 'connection-failure');
            }
        });
    };
    App.prototype.maybeShowAutoConnectDialog = function () {
        var dismissed = false;
        try {
            dismissed = this.settings.get(settings_1.SettingsKey.AUTO_CONNECT_DIALOG_DISMISSED) === 'true';
        } catch (e) {
            console.error("Failed to read auto-connect dialog status, assuming not dismissed: " + e);
        }
        if (!dismissed) {
            this.rootEl.$.serversView.$.autoConnectDialog.show();
        }
    };
    App.prototype.autoConnectDialogDismissed = function () {
        this.settings.set(settings_1.SettingsKey.AUTO_CONNECT_DIALOG_DISMISSED, 'true');
    };
    App.prototype.disconnectServer = function (event) {
        var _this = this;
        var serverId = event.detail.serverId;
        if (!serverId) {
            throw new Error("disconnectServer event had no server ID");
        }
        var server = this.getServerByServerId(serverId);
        var card = this.getCardByServerId(serverId);
        console.log("disconnecting from server " + serverId);
        card.state = 'DISCONNECTING';
        server.disconnect().then(function () {
            card.state = 'DISCONNECTED';
            console.log("disconnected from server " + serverId);
            _this.rootEl.showToast(_this.localize('server-disconnected', 'serverName', server.name));
        }, function (e) {
            card.state = 'CONNECTED';
            _this.showLocalizedError(e);
            console.warn("could not disconnect from server " + serverId + ": " + e.name);
        });
    };
    App.prototype.submitFeedback = function (event) {
        var _this = this;
        var formData = this.feedbackViewEl.getValidatedFormData();
        if (!formData) {
            return;
        }
        var feedback = formData.feedback,
            category = formData.category,
            email = formData.email;
        this.rootEl.$.feedbackView.submitting = true;
        this.errorReporter.report(feedback, category, email).then(function () {
            _this.rootEl.$.feedbackView.submitting = false;
            _this.rootEl.$.feedbackView.resetForm();
            _this.changeToDefaultPage();
            _this.rootEl.showToast(_this.rootEl.localize('feedback-thanks'));
        }, function (err) {
            _this.rootEl.$.feedbackView.submitting = false;
            _this.showLocalizedError(new errors.FeedbackSubmissionError());
        });
    };
    // EventQueue event handlers:
    App.prototype.showServerAdded = function (event) {
        var server = event.server;
        console.debug('Server added');
        this.syncServersToUI();
        this.syncServerConnectivityState(server);
        this.changeToDefaultPage();
        this.rootEl.showToast(this.localize('server-added', 'serverName', server.name));
    };
    App.prototype.showServerForgotten = function (event) {
        var _this = this;
        var server = event.server;
        console.debug('Server forgotten');
        this.syncServersToUI();
        this.rootEl.showToast(this.localize('server-forgotten', 'serverName', server.name), 10000, this.localize('undo-button-label'), function () {
            _this.serverRepo.undoForget(server.id);
        });
    };
    App.prototype.showServerForgetUndone = function (event) {
        this.syncServersToUI();
        var server = event.server;
        this.rootEl.showToast(this.localize('server-forgotten-undo', 'serverName', server.name));
    };
    App.prototype.showServerRenamed = function (event) {
        var server = event.server;
        console.debug('Server renamed');
        this.serverListEl.getServerCard(server.id).serverName = server.name;
        this.rootEl.showToast(this.localize('server-rename-complete'));
    };
    // Helpers:
    App.prototype.syncServersToUI = function () {
        this.rootEl.servers = this.serverRepo.getAll();
    };
    App.prototype.syncConnectivityStateToServerCards = function () {
        var e_1, _a;
        try {
            for (var _b = __values(this.serverRepo.getAll()), _c = _b.next(); !_c.done; _c = _b.next()) {
                var server = _c.value;
                this.syncServerConnectivityState(server);
            }
        } catch (e_1_1) {
            e_1 = { error: e_1_1 };
        } finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
            } finally {
                if (e_1) throw e_1.error;
            }
        }
    };
    App.prototype.syncServerConnectivityState = function (server) {
        var _this = this;
        server.checkRunning().then(function (isRunning) {
            var card = _this.serverListEl.getServerCard(server.id);
            if (!isRunning) {
                card.state = 'DISCONNECTED';
                return;
            }
            server.checkReachable().then(function (isReachable) {
                if (isReachable) {
                    card.state = 'CONNECTED';
                } else {
                    console.log("Server " + server.id + " reconnecting");
                    card.state = 'RECONNECTING';
                }
            });
        }).catch(function (e) {
            console.error('Failed to sync server connectivity state', e);
        });
    };
    App.prototype.registerUrlInterceptionListener = function (urlInterceptor) {
        var _this = this;
        urlInterceptor.registerListener(function (url) {
            if (!url || !unwrapInvite(url).startsWith('ss://')) {
                // This check is necessary to ignore empty and malformed install-referrer URLs in Android
                // while allowing ss:// and invite URLs.
                // TODO: Stop receiving install referrer intents so we can remove this.
                return console.debug("Ignoring intercepted non-shadowsocks url");
            }
            try {
                _this.confirmAddServer(url);
            } catch (err) {
                _this.showLocalizedErrorInDefaultPage(err);
            }
        });
    };
    App.prototype.changeToDefaultPage = function () {
        this.rootEl.changePage(this.rootEl.DEFAULT_PAGE);
    };
    // Returns the server having serverId, throws if the server cannot be found.
    App.prototype.getServerByServerId = function (serverId) {
        var server = this.serverRepo.getById(serverId);
        if (!server) {
            throw new Error("could not find server with ID " + serverId);
        }
        return server;
    };
    // Returns the card associated with serverId, throws if no such card exists.
    // See server-list.html.
    App.prototype.getCardByServerId = function (serverId) {
        return this.serverListEl.getServerCard(serverId);
    };
    App.prototype.showLocalizedErrorInDefaultPage = function (err) {
        this.changeToDefaultPage();
        this.showLocalizedError(err);
    };
    App.prototype.isWindows = function () {
        return !('cordova' in window);
    };
    return App;
}();
exports.App = App;

},{"../model/errors":33,"../model/events":34,"./settings":30,"ShadowsocksConfig/shadowsocks_config":1}],22:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
// Generic clipboard. Implementations should only have to implement getContents().
var AbstractClipboard = /** @class */function () {
    function AbstractClipboard() {
        this.listener = null;
    }
    AbstractClipboard.prototype.getContents = function () {
        return Promise.reject(new Error('unimplemented skeleton method'));
    };
    AbstractClipboard.prototype.setListener = function (listener) {
        this.listener = listener;
    };
    AbstractClipboard.prototype.emitEvent = function () {
        if (this.listener) {
            this.getContents().then(this.listener);
        }
    };
    return AbstractClipboard;
}();
exports.AbstractClipboard = AbstractClipboard;

},{}],23:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __extends = undefined && undefined.__extends || function () {
    var _extendStatics = function extendStatics(d, b) {
        _extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function (d, b) {
            d.__proto__ = b;
        } || function (d, b) {
            for (var p in b) {
                if (b.hasOwnProperty(p)) d[p] = b[p];
            }
        };
        return _extendStatics(d, b);
    };
    return function (d, b) {
        _extendStatics(d, b);
        function __() {
            this.constructor = d;
        }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
}();
Object.defineProperty(exports, "__esModule", { value: true });
/// <reference path='../../types/ambient/outlinePlugin.d.ts'/>
/// <reference path='../../types/ambient/webintents.d.ts'/>
var Raven = require("raven-js");
var clipboard_1 = require("./clipboard");
var error_reporter_1 = require("./error_reporter");
var fake_connection_1 = require("./fake_connection");
var main_1 = require("./main");
var outline_server_1 = require("./outline_server");
var updater_1 = require("./updater");
var interceptors = require("./url_interceptor");
// Pushes a clipboard event whenever the app is brought to the foreground.
var CordovaClipboard = /** @class */function (_super) {
    __extends(CordovaClipboard, _super);
    function CordovaClipboard() {
        var _this = _super.call(this) || this;
        document.addEventListener('resume', _this.emitEvent.bind(_this));
        return _this;
    }
    CordovaClipboard.prototype.getContents = function () {
        return new Promise(function (resolve, reject) {
            cordova.plugins.clipboard.paste(resolve, reject);
        });
    };
    return CordovaClipboard;
}(clipboard_1.AbstractClipboard);
// Adds reports from the (native) Cordova plugin.
var CordovaErrorReporter = /** @class */function (_super) {
    __extends(CordovaErrorReporter, _super);
    function CordovaErrorReporter(appVersion, appBuildNumber, dsn, nativeDsn) {
        var _this = _super.call(this, appVersion, dsn, { 'build.number': appBuildNumber }) || this;
        cordova.plugins.outline.log.initialize(nativeDsn).catch(console.error);
        return _this;
    }
    CordovaErrorReporter.prototype.report = function (userFeedback, feedbackCategory, userEmail) {
        return _super.prototype.report.call(this, userFeedback, feedbackCategory, userEmail).then(function () {
            return cordova.plugins.outline.log.send(Raven.lastEventId());
        });
    };
    return CordovaErrorReporter;
}(error_reporter_1.SentryErrorReporter);
exports.CordovaErrorReporter = CordovaErrorReporter;
// This class should only be instantiated after Cordova fires the deviceready event.
var CordovaPlatform = /** @class */function () {
    function CordovaPlatform() {}
    CordovaPlatform.isBrowser = function () {
        return device.platform === 'browser';
    };
    CordovaPlatform.prototype.hasDeviceSupport = function () {
        return !CordovaPlatform.isBrowser();
    };
    CordovaPlatform.prototype.getPersistentServerFactory = function () {
        var _this = this;
        return function (serverId, config, eventQueue) {
            return new outline_server_1.OutlineServer(serverId, config, _this.hasDeviceSupport() ? new cordova.plugins.outline.Connection(config, serverId) : new fake_connection_1.FakeOutlineConnection(config, serverId), eventQueue);
        };
    };
    CordovaPlatform.prototype.getUrlInterceptor = function () {
        if (device.platform === 'iOS' || device.platform === 'Mac OS X') {
            return new interceptors.AppleUrlInterceptor(appleLaunchUrl);
        } else if (device.platform === 'Android') {
            return new interceptors.AndroidUrlInterceptor();
        }
        console.warn('no intent interceptor available');
        return new interceptors.UrlInterceptor();
    };
    CordovaPlatform.prototype.getClipboard = function () {
        return new CordovaClipboard();
    };
    CordovaPlatform.prototype.getErrorReporter = function (env) {
        return this.hasDeviceSupport() ? new CordovaErrorReporter(env.APP_VERSION, env.APP_BUILD_NUMBER, env.SENTRY_DSN, env.SENTRY_NATIVE_DSN) : new error_reporter_1.SentryErrorReporter(env.APP_VERSION, env.SENTRY_DSN, {});
    };
    CordovaPlatform.prototype.getUpdater = function () {
        return new updater_1.AbstractUpdater();
    };
    CordovaPlatform.prototype.quitApplication = function () {
        // Only used in macOS because menu bar apps provide no alternative way of quitting.
        cordova.plugins.outline.quitApplication();
    };
    return CordovaPlatform;
}();
// https://cordova.apache.org/docs/en/latest/cordova/events/events.html#deviceready
var onceDeviceReady = new Promise(function (resolve) {
    document.addEventListener('deviceready', resolve);
});
// cordova-[ios|osx] call a global function with this signature when a URL is
// intercepted. We handle URL interceptions with an intent interceptor; however,
// when the app is launched via URL our start up sequence misses the call due to
// a race. Define the function temporarily here, and set a global variable.
var appleLaunchUrl;
window.handleOpenURL = function (url) {
    appleLaunchUrl = url;
};
onceDeviceReady.then(function () {
    main_1.main(new CordovaPlatform());
});

},{"./clipboard":22,"./error_reporter":25,"./fake_connection":26,"./main":27,"./outline_server":28,"./updater":31,"./url_interceptor":32,"raven-js":10}],24:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
// Keep these in sync with the EnvironmentVariables interface above.
var ENV_KEYS = {
    APP_VERSION: 'APP_VERSION',
    APP_BUILD_NUMBER: 'APP_BUILD_NUMBER',
    SENTRY_DSN: 'SENTRY_DSN',
    SENTRY_NATIVE_DSN: 'SENTRY_NATIVE_DSN'
};
function validateEnvVars(json) {
    for (var key in ENV_KEYS) {
        if (!json.hasOwnProperty(key)) {
            throw new Error("Missing environment variable: " + key);
        }
    }
}
// According to http://caniuse.com/#feat=fetch fetch didn't hit iOS Safari
// until v10.3 released 3/26/17, so use XMLHttpRequest instead.
exports.onceEnvVars = new Promise(function (resolve, reject) {
    var xhr = new XMLHttpRequest();
    xhr.onload = function () {
        try {
            var json = JSON.parse(xhr.responseText);
            validateEnvVars(json);
            console.debug('Resolving with envVars:', json);
            resolve(json);
        } catch (err) {
            reject(err);
        }
    };
    xhr.open('GET', 'environment.json', true);
    xhr.send();
});

},{}],25:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
var Raven = require("raven-js");
var SentryErrorReporter = /** @class */function () {
    function SentryErrorReporter(appVersion, dsn, tags) {
        Raven.config(dsn, { release: appVersion, 'tags': tags }).install();
        this.setUpUnhandledRejectionListener();
    }
    SentryErrorReporter.prototype.report = function (userFeedback, feedbackCategory, userEmail) {
        Raven.setUserContext({ email: userEmail || '' });
        Raven.captureMessage(userFeedback, { tags: { category: feedbackCategory } });
        Raven.setUserContext(); // Reset the user context, don't cache the email
        return Promise.resolve();
    };
    SentryErrorReporter.prototype.setUpUnhandledRejectionListener = function () {
        // Chrome is the only browser that supports the unhandledrejection event.
        // This is fine for Android, but will not work in iOS.
        var unhandledRejection = 'unhandledrejection';
        window.addEventListener(unhandledRejection, function (event) {
            var reason = event.reason;
            var msg = reason.stack ? reason.stack : reason;
            Raven.captureBreadcrumb({ message: msg, category: unhandledRejection });
        });
    };
    return SentryErrorReporter;
}();
exports.SentryErrorReporter = SentryErrorReporter;

},{"raven-js":10}],26:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
/// <reference path='../../types/ambient/outlinePlugin.d.ts'/>
var errors = require("../model/errors");
// Note that because this implementation does not emit disconnection events, "switching" between
// servers in the server list will not work as expected.
var FakeOutlineConnection = /** @class */function () {
    function FakeOutlineConnection(config, id) {
        this.config = config;
        this.id = id;
        this.running = false;
    }
    FakeOutlineConnection.prototype.playBroken = function () {
        return this.config.name && this.config.name.toLowerCase().includes('broken');
    };
    FakeOutlineConnection.prototype.playUnreachable = function () {
        return !(this.config.name && this.config.name.toLowerCase().includes('unreachable'));
    };
    FakeOutlineConnection.prototype.start = function () {
        if (this.running) {
            return Promise.resolve();
        }
        if (!this.playUnreachable()) {
            return Promise.reject(new errors.OutlinePluginError(5 /* SERVER_UNREACHABLE */));
        } else if (this.playBroken()) {
            return Promise.reject(new errors.OutlinePluginError(8 /* SHADOWSOCKS_START_FAILURE */));
        } else {
            this.running = true;
            return Promise.resolve();
        }
    };
    FakeOutlineConnection.prototype.stop = function () {
        if (!this.running) {
            return Promise.resolve();
        }
        this.running = false;
        return Promise.resolve();
    };
    FakeOutlineConnection.prototype.isRunning = function () {
        return Promise.resolve(this.running);
    };
    FakeOutlineConnection.prototype.isReachable = function () {
        return Promise.resolve(!this.playUnreachable());
    };
    FakeOutlineConnection.prototype.onStatusChange = function (listener) {
        // NOOP
    };
    return FakeOutlineConnection;
}();
exports.FakeOutlineConnection = FakeOutlineConnection;

},{"../model/errors":33}],27:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __read = undefined && undefined.__read || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o),
        r,
        ar = [],
        e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) {
            ar.push(r.value);
        }
    } catch (error) {
        e = { error: error };
    } finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        } finally {
            if (e) throw e.error;
        }
    }
    return ar;
};
Object.defineProperty(exports, "__esModule", { value: true });
var url = require("url");
var events_1 = require("../model/events");
var app_1 = require("./app");
var environment_1 = require("./environment");
var persistent_server_1 = require("./persistent_server");
var settings_1 = require("./settings");
// Used to determine whether to use Polymer functionality on app initialization failure.
var webComponentsAreReady = false;
document.addEventListener('WebComponentsReady', function () {
    console.debug('received WebComponentsReady event');
    webComponentsAreReady = true;
});
// Used to delay loading the app until (translation) resources have been loaded. This can happen a
// little later than WebComponentsReady.
var oncePolymerIsReady = new Promise(function (resolve) {
    document.addEventListener('app-localize-resources-loaded', function () {
        console.debug('received app-localize-resources-loaded event');
        resolve();
    });
});
// Helpers
// Do not call until WebComponentsReady has fired!
function getRootEl() {
    return document.querySelector('app-root');
}
function createServerRepo(eventQueue, storage, deviceSupport, connectionType) {
    var repo = new persistent_server_1.PersistentServerRepository(connectionType, eventQueue, storage);
    if (!deviceSupport) {
        console.debug('Detected development environment, using fake servers.');
        if (repo.getAll().length === 0) {
            repo.add({ name: 'Fake Working Server', host: '127.0.0.1' });
            repo.add({ name: 'Fake Broken Server', host: '192.0.2.1' });
            repo.add({ name: 'Fake Unreachable Server', host: '10.0.0.24' });
        }
    }
    return repo;
}
function main(platform) {
    return Promise.all([environment_1.onceEnvVars, oncePolymerIsReady]).then(function (_a) {
        var _b = __read(_a, 1),
            environmentVars = _b[0];
        console.debug('running main() function');
        var queryParams = url.parse(document.URL, true).query;
        var debugMode = queryParams.debug === 'true';
        var eventQueue = new events_1.EventQueue();
        var serverRepo = createServerRepo(eventQueue, window.localStorage, platform.hasDeviceSupport(), platform.getPersistentServerFactory());
        var settings = new settings_1.Settings();
        var app = new app_1.App(eventQueue, serverRepo, getRootEl(), debugMode, platform.getUrlInterceptor(), platform.getClipboard(), platform.getErrorReporter(environmentVars), settings, environmentVars, platform.getUpdater(), platform.quitApplication);
    }, function (e) {
        onUnexpectedError(e);
        throw e;
    });
}
exports.main = main;
function onUnexpectedError(error) {
    var rootEl = getRootEl();
    if (webComponentsAreReady && rootEl && rootEl.localize) {
        var localize = rootEl.localize.bind(rootEl);
        rootEl.showToast(localize('error-unexpected'), 120000);
    } else {
        // Something went terribly wrong (i.e. Polymer failed to initialize). Provide some messaging to
        // the user, even if we are not able to display it in a toast or localize it.
        // TODO: provide an help email once we have a domain.
        alert("An unexpected error occurred.");
    }
    console.error(error);
}
// Returns Polymer's localization function. Must be called after WebComponentsReady has fired.
function getLocalizationFunction() {
    var rootEl = getRootEl();
    if (!rootEl) {
        return null;
    }
    return rootEl.localize;
}
exports.getLocalizationFunction = getLocalizationFunction;

},{"../model/events":34,"./app":21,"./environment":24,"./persistent_server":29,"./settings":30,"url":14}],28:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
/// <reference path='../../types/ambient/outlinePlugin.d.ts'/>
var errors = require("../model/errors");
var events = require("../model/events");
var OutlineServer = /** @class */function () {
    function OutlineServer(id, config, connection, eventQueue) {
        var _this = this;
        this.id = id;
        this.config = config;
        this.connection = connection;
        this.eventQueue = eventQueue;
        this.connection.onStatusChange(function (status) {
            var statusEvent;
            switch (status) {
                case 0 /* CONNECTED */:
                    statusEvent = new events.ServerConnected(_this);
                    break;
                case 1 /* DISCONNECTED */:
                    statusEvent = new events.ServerDisconnected(_this);
                    break;
                case 2 /* RECONNECTING */:
                    statusEvent = new events.ServerReconnecting(_this);
                    break;
                default:
                    console.warn("Received unknown connection status " + status);
                    return;
            }
            eventQueue.enqueue(statusEvent);
        });
    }
    Object.defineProperty(OutlineServer.prototype, "name", {
        get: function get() {
            return this.config.name || this.config.host || '';
        },
        set: function set(newName) {
            this.config.name = newName;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OutlineServer.prototype, "host", {
        get: function get() {
            return this.config.host;
        },
        enumerable: true,
        configurable: true
    });
    OutlineServer.prototype.connect = function () {
        return this.connection.start().catch(function (e) {
            // e originates in "native" code: either Cordova or Electron's main process.
            // Because of this, we cannot assume "instanceof OutlinePluginError" will work.
            if (e.errorCode) {
                throw errors.fromErrorCode(e.errorCode);
            }
            throw e;
        });
    };
    OutlineServer.prototype.disconnect = function () {
        return this.connection.stop().catch(function (e) {
            // TODO: None of the plugins currently return an ErrorCode on disconnection.
            throw new errors.RegularNativeError();
        });
    };
    OutlineServer.prototype.checkRunning = function () {
        return this.connection.isRunning();
    };
    OutlineServer.prototype.checkReachable = function () {
        return this.connection.isReachable();
    };
    return OutlineServer;
}();
exports.OutlineServer = OutlineServer;

},{"../model/errors":33,"../model/events":34}],29:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __values = undefined && undefined.__values || function (o) {
    var m = typeof Symbol === "function" && o[Symbol.iterator],
        i = 0;
    if (m) return m.call(o);
    return {
        next: function next() {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
};
Object.defineProperty(exports, "__esModule", { value: true });
var uuid_1 = require("uuid");
var errors_1 = require("../model/errors");
var events = require("../model/events");
// Maintains a persisted set of servers and liaises with the core.
var PersistentServerRepository = /** @class */function () {
    function PersistentServerRepository(createServer, eventQueue, storage) {
        this.createServer = createServer;
        this.eventQueue = eventQueue;
        this.storage = storage;
        this.lastForgottenServer = null;
        this.loadServers();
    }
    PersistentServerRepository.prototype.getAll = function () {
        return Array.from(this.serverById.values());
    };
    PersistentServerRepository.prototype.getById = function (serverId) {
        return this.serverById.get(serverId);
    };
    PersistentServerRepository.prototype.add = function (serverConfig) {
        var alreadyAddedServer = this.serverFromConfig(serverConfig);
        if (alreadyAddedServer) {
            throw new errors_1.ServerAlreadyAdded(alreadyAddedServer);
        }
        var server = this.createServer(uuid_1.v4(), serverConfig, this.eventQueue);
        this.serverById.set(server.id, server);
        this.storeServers();
        this.eventQueue.enqueue(new events.ServerAdded(server));
    };
    PersistentServerRepository.prototype.rename = function (serverId, newName) {
        var server = this.serverById.get(serverId);
        if (!server) {
            console.warn("Cannot rename nonexistent server " + serverId);
            return;
        }
        server.name = newName;
        this.storeServers();
        this.eventQueue.enqueue(new events.ServerRenamed(server));
    };
    PersistentServerRepository.prototype.forget = function (serverId) {
        var server = this.serverById.get(serverId);
        if (!server) {
            console.warn("Cannot remove nonexistent server " + serverId);
            return;
        }
        this.serverById.delete(serverId);
        this.lastForgottenServer = server;
        this.storeServers();
        this.eventQueue.enqueue(new events.ServerForgotten(server));
    };
    PersistentServerRepository.prototype.undoForget = function (serverId) {
        if (!this.lastForgottenServer) {
            console.warn('No forgotten server to unforget');
            return;
        } else if (this.lastForgottenServer.id !== serverId) {
            console.warn('id of forgotten server', this.lastForgottenServer, 'does not match', serverId);
            return;
        }
        this.serverById.set(this.lastForgottenServer.id, this.lastForgottenServer);
        this.storeServers();
        this.eventQueue.enqueue(new events.ServerForgetUndone(this.lastForgottenServer));
        this.lastForgottenServer = null;
    };
    PersistentServerRepository.prototype.containsServer = function (config) {
        return !!this.serverFromConfig(config);
    };
    PersistentServerRepository.prototype.serverFromConfig = function (config) {
        var e_1, _a;
        try {
            for (var _b = __values(this.getAll()), _c = _b.next(); !_c.done; _c = _b.next()) {
                var server = _c.value;
                if (configsMatch(server.config, config)) {
                    return server;
                }
            }
        } catch (e_1_1) {
            e_1 = { error: e_1_1 };
        } finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
            } finally {
                if (e_1) throw e_1.error;
            }
        }
    };
    PersistentServerRepository.prototype.storeServers = function () {
        var e_2, _a;
        var configById = {};
        try {
            for (var _b = __values(this.serverById.values()), _c = _b.next(); !_c.done; _c = _b.next()) {
                var server = _c.value;
                configById[server.id] = server.config;
            }
        } catch (e_2_1) {
            e_2 = { error: e_2_1 };
        } finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
            } finally {
                if (e_2) throw e_2.error;
            }
        }
        var json = JSON.stringify(configById);
        this.storage.setItem(PersistentServerRepository.SERVERS_STORAGE_KEY, json);
    };
    // Loads servers from storage,
    // raising an error if there is any problem loading.
    PersistentServerRepository.prototype.loadServers = function () {
        this.serverById = new Map();
        var serversJson = this.storage.getItem(PersistentServerRepository.SERVERS_STORAGE_KEY);
        if (!serversJson) {
            console.debug("no servers found in storage");
            return;
        }
        var configById = {};
        try {
            configById = JSON.parse(serversJson);
        } catch (e) {
            throw new Error("could not parse saved servers: " + e.message);
        }
        for (var serverId in configById) {
            if (configById.hasOwnProperty(serverId)) {
                var config = configById[serverId];
                try {
                    var server = this.createServer(serverId, config, this.eventQueue);
                    this.serverById.set(serverId, server);
                } catch (e) {
                    // Don't propagate so other stored servers can be created.
                    console.error(e);
                }
            }
        }
    };
    // Name by which servers are saved to storage.
    PersistentServerRepository.SERVERS_STORAGE_KEY = 'servers';
    return PersistentServerRepository;
}();
exports.PersistentServerRepository = PersistentServerRepository;
function configsMatch(left, right) {
    return left.host === right.host && left.port === right.port && left.method === right.method && left.password === right.password;
}

},{"../model/errors":33,"../model/events":34,"uuid":16}],30:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __values = undefined && undefined.__values || function (o) {
    var m = typeof Symbol === "function" && o[Symbol.iterator],
        i = 0;
    if (m) return m.call(o);
    return {
        next: function next() {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
};
var __read = undefined && undefined.__read || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o),
        r,
        ar = [],
        e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) {
            ar.push(r.value);
        }
    } catch (error) {
        e = { error: error };
    } finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        } finally {
            if (e) throw e.error;
        }
    }
    return ar;
};
Object.defineProperty(exports, "__esModule", { value: true });
// Setting keys supported by the `Settings` class.
var SettingsKey;
(function (SettingsKey) {
    SettingsKey["VPN_WARNING_DISMISSED"] = "vpn-warning-dismissed";
    SettingsKey["AUTO_CONNECT_DIALOG_DISMISSED"] = "auto-connect-dialog-dismissed";
    SettingsKey["PRIVACY_ACK"] = "privacy-ack";
})(SettingsKey = exports.SettingsKey || (exports.SettingsKey = {}));
// Persistent storage for user settings that supports a limited set of keys.
var Settings = /** @class */function () {
    function Settings(storage, validKeys) {
        if (storage === void 0) {
            storage = window.localStorage;
        }
        if (validKeys === void 0) {
            validKeys = Object.values(SettingsKey);
        }
        this.storage = storage;
        this.validKeys = validKeys;
        this.settings = new Map();
        this.loadSettings();
    }
    Settings.prototype.get = function (key) {
        return this.settings.get(key);
    };
    Settings.prototype.set = function (key, value) {
        if (!this.isValidSetting(key)) {
            throw new Error("Cannot set invalid key " + key);
        }
        this.settings.set(key, value);
        this.storeSettings();
    };
    Settings.prototype.remove = function (key) {
        this.settings.delete(key);
        this.storeSettings();
    };
    Settings.prototype.isValidSetting = function (key) {
        return this.validKeys.includes(key);
    };
    Settings.prototype.loadSettings = function () {
        var settingsJson = this.storage.getItem(Settings.STORAGE_KEY);
        if (!settingsJson) {
            console.debug("No settings found in storage");
            return;
        }
        var storageSettings = JSON.parse(settingsJson);
        for (var key in storageSettings) {
            if (storageSettings.hasOwnProperty(key)) {
                this.settings.set(key, storageSettings[key]);
            }
        }
    };
    Settings.prototype.storeSettings = function () {
        var e_1, _a;
        var storageSettings = {};
        try {
            for (var _b = __values(this.settings), _c = _b.next(); !_c.done; _c = _b.next()) {
                var _d = __read(_c.value, 2),
                    key = _d[0],
                    value = _d[1];
                storageSettings[key] = value;
            }
        } catch (e_1_1) {
            e_1 = { error: e_1_1 };
        } finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
            } finally {
                if (e_1) throw e_1.error;
            }
        }
        var storageSettingsJson = JSON.stringify(storageSettings);
        this.storage.setItem(Settings.STORAGE_KEY, storageSettingsJson);
    };
    Settings.STORAGE_KEY = 'settings';
    return Settings;
}();
exports.Settings = Settings;

},{}],31:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
var AbstractUpdater = /** @class */function () {
    function AbstractUpdater() {
        this.listener = null;
    }
    AbstractUpdater.prototype.setListener = function (listener) {
        this.listener = listener;
    };
    AbstractUpdater.prototype.emitEvent = function () {
        if (this.listener) {
            this.listener();
        }
    };
    return AbstractUpdater;
}();
exports.AbstractUpdater = AbstractUpdater;

},{}],32:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __extends = undefined && undefined.__extends || function () {
    var _extendStatics = function extendStatics(d, b) {
        _extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function (d, b) {
            d.__proto__ = b;
        } || function (d, b) {
            for (var p in b) {
                if (b.hasOwnProperty(p)) d[p] = b[p];
            }
        };
        return _extendStatics(d, b);
    };
    return function (d, b) {
        _extendStatics(d, b);
        function __() {
            this.constructor = d;
        }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
}();
var __values = undefined && undefined.__values || function (o) {
    var m = typeof Symbol === "function" && o[Symbol.iterator],
        i = 0;
    if (m) return m.call(o);
    return {
        next: function next() {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
};
Object.defineProperty(exports, "__esModule", { value: true });
/// <reference path='../../types/ambient/webintents.d.ts'/>
var UrlInterceptor = /** @class */function () {
    function UrlInterceptor() {
        this.listeners = [];
    }
    UrlInterceptor.prototype.registerListener = function (listener) {
        this.listeners.push(listener);
        if (this.launchUrl) {
            listener(this.launchUrl);
            this.launchUrl = undefined;
        }
    };
    UrlInterceptor.prototype.executeListeners = function (url) {
        var e_1, _a;
        if (!url) {
            return;
        }
        if (!this.listeners.length) {
            console.log('no listeners have been added, delaying intent firing');
            this.launchUrl = url;
            return;
        }
        try {
            for (var _b = __values(this.listeners), _c = _b.next(); !_c.done; _c = _b.next()) {
                var listener = _c.value;
                listener(url);
            }
        } catch (e_1_1) {
            e_1 = { error: e_1_1 };
        } finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
            } finally {
                if (e_1) throw e_1.error;
            }
        }
    };
    return UrlInterceptor;
}();
exports.UrlInterceptor = UrlInterceptor;
var AndroidUrlInterceptor = /** @class */function (_super) {
    __extends(AndroidUrlInterceptor, _super);
    function AndroidUrlInterceptor() {
        var _this = _super.call(this) || this;
        window.webintent.getUri(function (launchUrl) {
            window.webintent.onNewIntent(_this.executeListeners.bind(_this));
            _this.executeListeners(launchUrl);
        });
        return _this;
    }
    return AndroidUrlInterceptor;
}(UrlInterceptor);
exports.AndroidUrlInterceptor = AndroidUrlInterceptor;
var AppleUrlInterceptor = /** @class */function (_super) {
    __extends(AppleUrlInterceptor, _super);
    function AppleUrlInterceptor(launchUrl) {
        var _this = _super.call(this) || this;
        // cordova-[ios|osx] call a global function with this signature when a URL is intercepted.
        // We define it in |cordova_main|, redefine it to use this interceptor.
        window.handleOpenURL = function (url) {
            _this.executeListeners(url);
        };
        if (launchUrl) {
            _this.executeListeners(launchUrl);
        }
        return _this;
    }
    return AppleUrlInterceptor;
}(UrlInterceptor);
exports.AppleUrlInterceptor = AppleUrlInterceptor;

},{}],33:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __extends = undefined && undefined.__extends || function () {
    var _extendStatics = function extendStatics(d, b) {
        _extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function (d, b) {
            d.__proto__ = b;
        } || function (d, b) {
            for (var p in b) {
                if (b.hasOwnProperty(p)) d[p] = b[p];
            }
        };
        return _extendStatics(d, b);
    };
    return function (d, b) {
        _extendStatics(d, b);
        function __() {
            this.constructor = d;
        }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
}();
Object.defineProperty(exports, "__esModule", { value: true });
var OutlineError = /** @class */function (_super) {
    __extends(OutlineError, _super);
    function OutlineError(message) {
        var _newTarget = this.constructor;
        var _this =
        // ref:
        // https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-2.html#support-for-newtarget
        _super.call(this, message) || this;
        Object.setPrototypeOf(_this, _newTarget.prototype); // restore prototype chain
        _this.name = _newTarget.name;
        return _this;
    }
    return OutlineError;
}(Error);
exports.OutlineError = OutlineError;
var ServerAlreadyAdded = /** @class */function (_super) {
    __extends(ServerAlreadyAdded, _super);
    function ServerAlreadyAdded(server) {
        var _this = _super.call(this) || this;
        _this.server = server;
        return _this;
    }
    return ServerAlreadyAdded;
}(OutlineError);
exports.ServerAlreadyAdded = ServerAlreadyAdded;
var ServerIncompatible = /** @class */function (_super) {
    __extends(ServerIncompatible, _super);
    function ServerIncompatible(message) {
        return _super.call(this, message) || this;
    }
    return ServerIncompatible;
}(OutlineError);
exports.ServerIncompatible = ServerIncompatible;
var ServerUrlInvalid = /** @class */function (_super) {
    __extends(ServerUrlInvalid, _super);
    function ServerUrlInvalid(message) {
        return _super.call(this, message) || this;
    }
    return ServerUrlInvalid;
}(OutlineError);
exports.ServerUrlInvalid = ServerUrlInvalid;
var OperationTimedOut = /** @class */function (_super) {
    __extends(OperationTimedOut, _super);
    function OperationTimedOut(timeoutMs, operationName) {
        var _this = _super.call(this) || this;
        _this.timeoutMs = timeoutMs;
        _this.operationName = operationName;
        return _this;
    }
    return OperationTimedOut;
}(OutlineError);
exports.OperationTimedOut = OperationTimedOut;
var FeedbackSubmissionError = /** @class */function (_super) {
    __extends(FeedbackSubmissionError, _super);
    function FeedbackSubmissionError() {
        return _super.call(this) || this;
    }
    return FeedbackSubmissionError;
}(OutlineError);
exports.FeedbackSubmissionError = FeedbackSubmissionError;
// Error thrown by "native" code.
//
// Must be kept in sync with its Cordova doppelganger:
//   cordova-plugin-outline/outlinePlugin.js
//
// TODO: Rename this class, "plugin" is a poor name since the Electron apps do not have plugins.
var OutlinePluginError = /** @class */function (_super) {
    __extends(OutlinePluginError, _super);
    function OutlinePluginError(errorCode) {
        var _this = _super.call(this) || this;
        _this.errorCode = errorCode;
        return _this;
    }
    return OutlinePluginError;
}(OutlineError);
exports.OutlinePluginError = OutlinePluginError;
// Marker class for errors originating in native code.
// Bifurcates into two subclasses:
//  - "expected" errors originating in native code, e.g. incorrect password
//  - "unexpected" errors originating in native code, e.g. unhandled routing table
var NativeError = /** @class */function (_super) {
    __extends(NativeError, _super);
    function NativeError() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return NativeError;
}(OutlineError);
exports.NativeError = NativeError;
var RegularNativeError = /** @class */function (_super) {
    __extends(RegularNativeError, _super);
    function RegularNativeError() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return RegularNativeError;
}(NativeError);
exports.RegularNativeError = RegularNativeError;
var RedFlagNativeError = /** @class */function (_super) {
    __extends(RedFlagNativeError, _super);
    function RedFlagNativeError() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return RedFlagNativeError;
}(NativeError);
exports.RedFlagNativeError = RedFlagNativeError;
//////
// "Expected" errors.
//////
var UnexpectedPluginError = /** @class */function (_super) {
    __extends(UnexpectedPluginError, _super);
    function UnexpectedPluginError() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return UnexpectedPluginError;
}(RegularNativeError);
exports.UnexpectedPluginError = UnexpectedPluginError;
var VpnPermissionNotGranted = /** @class */function (_super) {
    __extends(VpnPermissionNotGranted, _super);
    function VpnPermissionNotGranted() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return VpnPermissionNotGranted;
}(RegularNativeError);
exports.VpnPermissionNotGranted = VpnPermissionNotGranted;
var InvalidServerCredentials = /** @class */function (_super) {
    __extends(InvalidServerCredentials, _super);
    function InvalidServerCredentials() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return InvalidServerCredentials;
}(RegularNativeError);
exports.InvalidServerCredentials = InvalidServerCredentials;
var RemoteUdpForwardingDisabled = /** @class */function (_super) {
    __extends(RemoteUdpForwardingDisabled, _super);
    function RemoteUdpForwardingDisabled() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return RemoteUdpForwardingDisabled;
}(RegularNativeError);
exports.RemoteUdpForwardingDisabled = RemoteUdpForwardingDisabled;
var ServerUnreachable = /** @class */function (_super) {
    __extends(ServerUnreachable, _super);
    function ServerUnreachable() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return ServerUnreachable;
}(RegularNativeError);
exports.ServerUnreachable = ServerUnreachable;
var IllegalServerConfiguration = /** @class */function (_super) {
    __extends(IllegalServerConfiguration, _super);
    function IllegalServerConfiguration() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return IllegalServerConfiguration;
}(RegularNativeError);
exports.IllegalServerConfiguration = IllegalServerConfiguration;
var NoAdminPermissions = /** @class */function (_super) {
    __extends(NoAdminPermissions, _super);
    function NoAdminPermissions() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return NoAdminPermissions;
}(RegularNativeError);
exports.NoAdminPermissions = NoAdminPermissions;
var SystemConfigurationException = /** @class */function (_super) {
    __extends(SystemConfigurationException, _super);
    function SystemConfigurationException() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return SystemConfigurationException;
}(RegularNativeError);
exports.SystemConfigurationException = SystemConfigurationException;
//////
// Now, "unexpected" errors.
// Use these sparingly because each occurrence triggers a Sentry report.
//////
// Windows.
var ShadowsocksStartFailure = /** @class */function (_super) {
    __extends(ShadowsocksStartFailure, _super);
    function ShadowsocksStartFailure() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return ShadowsocksStartFailure;
}(RedFlagNativeError);
exports.ShadowsocksStartFailure = ShadowsocksStartFailure;
var ConfigureSystemProxyFailure = /** @class */function (_super) {
    __extends(ConfigureSystemProxyFailure, _super);
    function ConfigureSystemProxyFailure() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return ConfigureSystemProxyFailure;
}(RedFlagNativeError);
exports.ConfigureSystemProxyFailure = ConfigureSystemProxyFailure;
var UnsupportedRoutingTable = /** @class */function (_super) {
    __extends(UnsupportedRoutingTable, _super);
    function UnsupportedRoutingTable() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return UnsupportedRoutingTable;
}(RedFlagNativeError);
exports.UnsupportedRoutingTable = UnsupportedRoutingTable;
// Used on Android and Apple to indicate that the plugin failed to establish the VPN tunnel.
var VpnStartFailure = /** @class */function (_super) {
    __extends(VpnStartFailure, _super);
    function VpnStartFailure() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return VpnStartFailure;
}(RedFlagNativeError);
exports.VpnStartFailure = VpnStartFailure;
// Converts an ErrorCode - originating in "native" code - to an instance of the relevant
// OutlineError subclass.
// Throws if the error code is not one defined in ErrorCode or is ErrorCode.NO_ERROR.
function fromErrorCode(errorCode) {
    switch (errorCode) {
        case 1 /* UNEXPECTED */:
            return new UnexpectedPluginError();
        case 2 /* VPN_PERMISSION_NOT_GRANTED */:
            return new VpnPermissionNotGranted();
        case 3 /* INVALID_SERVER_CREDENTIALS */:
            return new InvalidServerCredentials();
        case 4 /* UDP_RELAY_NOT_ENABLED */:
            return new RemoteUdpForwardingDisabled();
        case 5 /* SERVER_UNREACHABLE */:
            return new ServerUnreachable();
        case 6 /* VPN_START_FAILURE */:
            return new VpnStartFailure();
        case 7 /* ILLEGAL_SERVER_CONFIGURATION */:
            return new IllegalServerConfiguration();
        case 8 /* SHADOWSOCKS_START_FAILURE */:
            return new ShadowsocksStartFailure();
        case 9 /* CONFIGURE_SYSTEM_PROXY_FAILURE */:
            return new ConfigureSystemProxyFailure();
        case 10 /* NO_ADMIN_PERMISSIONS */:
            return new NoAdminPermissions();
        case 11 /* UNSUPPORTED_ROUTING_TABLE */:
            return new UnsupportedRoutingTable();
        case 12 /* SYSTEM_MISCONFIGURED */:
            return new SystemConfigurationException();
        default:
            throw new Error("unknown ErrorCode " + errorCode);
    }
}
exports.fromErrorCode = fromErrorCode;
// Converts a NativeError to an ErrorCode.
// Throws if the error is not a subclass of NativeError.
function toErrorCode(e) {
    if (e instanceof UnexpectedPluginError) {
        return 1 /* UNEXPECTED */;
    } else if (e instanceof VpnPermissionNotGranted) {
        return 2 /* VPN_PERMISSION_NOT_GRANTED */;
    } else if (e instanceof InvalidServerCredentials) {
        return 3 /* INVALID_SERVER_CREDENTIALS */;
    } else if (e instanceof RemoteUdpForwardingDisabled) {
        return 4 /* UDP_RELAY_NOT_ENABLED */;
    } else if (e instanceof ServerUnreachable) {
        return 5 /* SERVER_UNREACHABLE */;
    } else if (e instanceof VpnStartFailure) {
        return 6 /* VPN_START_FAILURE */;
    } else if (e instanceof IllegalServerConfiguration) {
        return 7 /* ILLEGAL_SERVER_CONFIGURATION */;
    } else if (e instanceof ShadowsocksStartFailure) {
        return 8 /* SHADOWSOCKS_START_FAILURE */;
    } else if (e instanceof ConfigureSystemProxyFailure) {
        return 9 /* CONFIGURE_SYSTEM_PROXY_FAILURE */;
    } else if (e instanceof UnsupportedRoutingTable) {
        return 11 /* UNSUPPORTED_ROUTING_TABLE */;
    } else if (e instanceof NoAdminPermissions) {
        return 10 /* NO_ADMIN_PERMISSIONS */;
    } else if (e instanceof SystemConfigurationException) {
        return 12 /* SYSTEM_MISCONFIGURED */;
    }
    throw new Error("unknown NativeError " + e.name);
}
exports.toErrorCode = toErrorCode;

},{}],34:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __values = undefined && undefined.__values || function (o) {
    var m = typeof Symbol === "function" && o[Symbol.iterator],
        i = 0;
    if (m) return m.call(o);
    return {
        next: function next() {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
};
Object.defineProperty(exports, "__esModule", { value: true });
var ServerAdded = /** @class */function () {
    function ServerAdded(server) {
        this.server = server;
    }
    return ServerAdded;
}();
exports.ServerAdded = ServerAdded;
var ServerAlreadyAdded = /** @class */function () {
    function ServerAlreadyAdded(server) {
        this.server = server;
    }
    return ServerAlreadyAdded;
}();
exports.ServerAlreadyAdded = ServerAlreadyAdded;
var ServerForgotten = /** @class */function () {
    function ServerForgotten(server) {
        this.server = server;
    }
    return ServerForgotten;
}();
exports.ServerForgotten = ServerForgotten;
var ServerForgetUndone = /** @class */function () {
    function ServerForgetUndone(server) {
        this.server = server;
    }
    return ServerForgetUndone;
}();
exports.ServerForgetUndone = ServerForgetUndone;
var ServerRenamed = /** @class */function () {
    function ServerRenamed(server) {
        this.server = server;
    }
    return ServerRenamed;
}();
exports.ServerRenamed = ServerRenamed;
var ServerUrlInvalid = /** @class */function () {
    function ServerUrlInvalid(serverUrl) {
        this.serverUrl = serverUrl;
    }
    return ServerUrlInvalid;
}();
exports.ServerUrlInvalid = ServerUrlInvalid;
var ServerConnected = /** @class */function () {
    function ServerConnected(server) {
        this.server = server;
    }
    return ServerConnected;
}();
exports.ServerConnected = ServerConnected;
var ServerDisconnected = /** @class */function () {
    function ServerDisconnected(server) {
        this.server = server;
    }
    return ServerDisconnected;
}();
exports.ServerDisconnected = ServerDisconnected;
var ServerReconnecting = /** @class */function () {
    function ServerReconnecting(server) {
        this.server = server;
    }
    return ServerReconnecting;
}();
exports.ServerReconnecting = ServerReconnecting;
// Simple publisher-subscriber queue.
var EventQueue = /** @class */function () {
    function EventQueue() {
        this.queuedEvents = [];
        this.listenersByEventType = new Map();
        this.isStarted = false;
        this.isPublishing = false;
    }
    EventQueue.prototype.startPublishing = function () {
        this.isStarted = true;
        this.publishQueuedEvents();
    };
    // Registers a listener for events of the type of the given constructor.
    EventQueue.prototype.subscribe = function (eventType, listener) {
        var listeners = this.listenersByEventType.get(eventType);
        if (!listeners) {
            listeners = [];
            this.listenersByEventType.set(eventType, listeners);
        }
        listeners.push(listener);
    };
    // Enqueues the given event for publishing and publishes all queued events if
    // publishing is not already happening.
    //
    // The enqueue method is reentrant: it may be called by an event listener
    // during the publishing of the events. In that case the method adds the event
    // to the end of the queue and returns immediately.
    //
    // This guarantees that events are published and handled in the order that
    // they are queued.
    //
    // There's no guarantee that the subscribers for the event have been called by
    // the time this function returns.
    EventQueue.prototype.enqueue = function (event) {
        this.queuedEvents.push(event);
        if (this.isStarted) {
            this.publishQueuedEvents();
        }
    };
    // Triggers the subscribers for all the enqueued events.
    EventQueue.prototype.publishQueuedEvents = function () {
        var e_1, _a;
        if (this.isPublishing) return;
        this.isPublishing = true;
        while (this.queuedEvents.length > 0) {
            var event_1 = this.queuedEvents.shift();
            var listeners = this.listenersByEventType.get(event_1.constructor);
            if (!listeners) {
                console.warn('Dropping event with no listeners:', event_1);
                continue;
            }
            try {
                for (var listeners_1 = __values(listeners), listeners_1_1 = listeners_1.next(); !listeners_1_1.done; listeners_1_1 = listeners_1.next()) {
                    var listener = listeners_1_1.value;
                    listener(event_1);
                }
            } catch (e_1_1) {
                e_1 = { error: e_1_1 };
            } finally {
                try {
                    if (listeners_1_1 && !listeners_1_1.done && (_a = listeners_1.return)) _a.call(listeners_1);
                } finally {
                    if (e_1) throw e_1.error;
                }
            }
        }
        this.isPublishing = false;
    };
    return EventQueue;
}();
exports.EventQueue = EventQueue;

},{}]},{},[23])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJub2RlX21vZHVsZXMvU2hhZG93c29ja3NDb25maWcvc2hhZG93c29ja3NfY29uZmlnLnRzIiwibm9kZV9tb2R1bGVzL2Jhc2UtNjQvYmFzZTY0LmpzIiwibm9kZV9tb2R1bGVzL3B1bnljb2RlL3B1bnljb2RlLmpzIiwibm9kZV9tb2R1bGVzL3F1ZXJ5c3RyaW5nLWVzMy9kZWNvZGUuanMiLCJub2RlX21vZHVsZXMvcXVlcnlzdHJpbmctZXMzL2VuY29kZS5qcyIsIm5vZGVfbW9kdWxlcy9xdWVyeXN0cmluZy1lczMvaW5kZXguanMiLCJub2RlX21vZHVsZXMvcmF2ZW4tanMvc3JjL2NvbmZpZ0Vycm9yLmpzIiwibm9kZV9tb2R1bGVzL3JhdmVuLWpzL3NyYy9jb25zb2xlLmpzIiwibm9kZV9tb2R1bGVzL3JhdmVuLWpzL3NyYy9yYXZlbi5qcyIsIm5vZGVfbW9kdWxlcy9yYXZlbi1qcy9zcmMvc2luZ2xldG9uLmpzIiwibm9kZV9tb2R1bGVzL3JhdmVuLWpzL3NyYy91dGlscy5qcyIsIm5vZGVfbW9kdWxlcy9yYXZlbi1qcy92ZW5kb3IvVHJhY2VLaXQvdHJhY2VraXQuanMiLCJub2RlX21vZHVsZXMvcmF2ZW4tanMvdmVuZG9yL2pzb24tc3RyaW5naWZ5LXNhZmUvc3RyaW5naWZ5LmpzIiwibm9kZV9tb2R1bGVzL3VybC91cmwuanMiLCJub2RlX21vZHVsZXMvdXJsL3V0aWwuanMiLCJub2RlX21vZHVsZXMvdXVpZC9pbmRleC5qcyIsIm5vZGVfbW9kdWxlcy91dWlkL2xpYi9ieXRlc1RvVXVpZC5qcyIsIm5vZGVfbW9kdWxlcy91dWlkL2xpYi9ybmctYnJvd3Nlci5qcyIsIm5vZGVfbW9kdWxlcy91dWlkL3YxLmpzIiwibm9kZV9tb2R1bGVzL3V1aWQvdjQuanMiLCJ3d3cvYXBwL2FwcC5qcyIsInd3dy9hcHAvY2xpcGJvYXJkLmpzIiwid3d3L2FwcC9jb3Jkb3ZhX21haW4uanMiLCJ3d3cvYXBwL2Vudmlyb25tZW50LmpzIiwid3d3L2FwcC9lcnJvcl9yZXBvcnRlci5qcyIsInd3dy9hcHAvZmFrZV9jb25uZWN0aW9uLmpzIiwid3d3L2FwcC9tYWluLmpzIiwid3d3L2FwcC9vdXRsaW5lX3NlcnZlci5qcyIsInd3dy9hcHAvcGVyc2lzdGVudF9zZXJ2ZXIuanMiLCJ3d3cvYXBwL3NldHRpbmdzLmpzIiwid3d3L2FwcC91cGRhdGVyLmpzIiwid3d3L2FwcC91cmxfaW50ZXJjZXB0b3IuanMiLCJ3d3cvbW9kZWwvZXJyb3JzLmpzIiwid3d3L21vZGVsL2V2ZW50cy5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7QUNBQSxBQUFxQztBQUNyQyxBQUFFO0FBQ0YsQUFBa0U7QUFDbEUsQUFBbUU7QUFDbkUsQUFBMEM7QUFDMUMsQUFBRTtBQUNGLEFBQWtEO0FBQ2xELEFBQUU7QUFDRixBQUFzRTtBQUN0RSxBQUFvRTtBQUNwRSxBQUEyRTtBQUMzRSxBQUFzRTtBQUN0RSxBQUFpQzs7Ozs7Ozs7Ozs7Ozs7Ozs7O2lCQUVqQztRQUFvQix1REFDcEI7QUFBTSxZQUFTLE9BQUcsQUFBTyxXQUFNLEFBQUssZUFBVyxBQUFDO21CQUNqQyxBQUFHLE9BQVMsQUFBQyxBQUFDLEFBQUMsUUFBOUIsQUFBTSxDQUE0QixBQUFDLEFBQUMsQUFBQyxBQUFPLEFBQUMsQUFBUyxBQUFDLEFBQUMsQUFBTSxBQUFDLEFBQy9ELEFBQU07ZUFBUyxJQUFHLE9BQVMsQUFBQyxBQUFDLEFBQUMsQUFBSSxXQUFDLEFBQUMsQUFBQyxBQUFPLEFBQUM7QUFDcEMsQUFBRyxtQkFBUyxBQUFDLEFBQUMsT0FEK0IsQUFBQyxBQUFDLEFBQU0sQUFBQyxBQUMvRCxBQUFNLENBQWtCLEFBQU0sQUFBQyxBQUFHLEFBQUMsQUFBQyxBQUFDLEFBQU8sQUFBQyxBQUFLLEFBQUMsQUFBQyxBQUFHLEFBQUMsQUFDeEQsQUFBTTtBQUFRLEFBQUcsQUFBUyxBQUFDLEFBQUMsQUFBRSxBQUFjLEFBQUMsQUFBUSxBQUFDLEFB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eEM7QUFDSjtBQUNELGFBQUssWUFBTCxHQUFvQixLQUFwQjtBQUNILEtBM0JEO0FBNEJBLFdBQU8sVUFBUDtBQUNILENBcEUrQixFQUFoQztBQXFFQSxRQUFRLFVBQVIsR0FBcUIsVUFBckIiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXNDb250ZW50IjpbIihmdW5jdGlvbiBlKHQsbixyKXtmdW5jdGlvbiBzKG8sdSl7aWYoIW5bb10pe2lmKCF0W29dKXt2YXIgYT10eXBlb2YgcmVxdWlyZT09XCJmdW5jdGlvblwiJiZyZXF1aXJlO2lmKCF1JiZhKXJldHVybiBhKG8sITApO2lmKGkpcmV0dXJuIGkobywhMCk7dmFyIGY9bmV3IEVycm9yKFwiQ2Fubm90IGZpbmQgbW9kdWxlICdcIitvK1wiJ1wiKTt0aHJvdyBmLmNvZGU9XCJNT0RVTEVfTk9UX0ZPVU5EXCIsZn12YXIgbD1uW29dPXtleHBvcnRzOnt9fTt0W29dWzBdLmNhbGwobC5leHBvcnRzLGZ1bmN0aW9uKGUpe3ZhciBuPXRbb11bMV1bZV07cmV0dXJuIHMobj9uOmUpfSxsLGwuZXhwb3J0cyxlLHQsbixyKX1yZXR1cm4gbltvXS5leHBvcnRzfXZhciBpPXR5cGVvZiByZXF1aXJlPT1cImZ1bmN0aW9uXCImJnJlcXVpcmU7Zm9yKHZhciBvPTA7bzxyLmxlbmd0aDtvKyspcyhyW29dKTtyZXR1cm4gc30pIiwiLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG5cbi8qIHRzbGludDpkaXNhYmxlICovXG5jb25zdCBpc0Jyb3dzZXIgPSB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJztcbmNvbnN0IGI2NEVuY29kZSA9IGlzQnJvd3NlciA/IGJ0b2EgOiByZXF1aXJlKCdiYXNlLTY0JykuZW5jb2RlO1xuY29uc3QgYjY0RGVjb2RlID0gaXNCcm93c2VyID8gYXRvYiA6IHJlcXVpcmUoJ2Jhc2UtNjQnKS5kZWNvZGU7XG5jb25zdCBVUkwgPSBpc0Jyb3dzZXIgPyB3aW5kb3cuVVJMIDogcmVxdWlyZSgndXJsJykuVVJMO1xuY29uc3QgcHVueWNvZGUgPSBpc0Jyb3dzZXIgPyAod2luZG93IGFzIGFueSkucHVueWNvZGUgOiByZXF1aXJlKCdwdW55Y29kZScpO1xuaWYgKCFwdW55Y29kZSkge1xuICB0aHJvdyBuZXcgRXJyb3IoYENvdWxkIG5vdCBmaW5kIHB1bnljb2RlLiBEaWQgeW91IGZvcmdldCB0byBhZGQgZS5nLlxuICA8c2NyaXB0IHNyYz1cImJvd2VyX2NvbXBvbmVudHMvcHVueWNvZGUvcHVueWNvZGUubWluLmpzXCI+PC9zY3JpcHQ+P2ApO1xufVxuLyogdHNsaW50OmVuYWJsZSAqL1xuXG4vLyBDdXN0b20gZXJyb3IgYmFzZSBjbGFzc1xuZXhwb3J0IGNsYXNzIFNoYWRvd3NvY2tzQ29uZmlnRXJyb3IgZXh0ZW5kcyBFcnJvciB7XG4gIGNvbnN0cnVjdG9yKG1lc3NhZ2U6IHN0cmluZykge1xuICAgIHN1cGVyKG1lc3NhZ2UpOyAgLy8gJ0Vycm9yJyBicmVha3MgcHJvdG90eXBlIGNoYWluIGhlcmUgaWYgdGhpcyBpcyB0cmFuc3BpbGVkIHRvIGVzNVxuICAgIE9iamVjdC5zZXRQcm90b3R5cGVPZih0aGlzLCBuZXcudGFyZ2V0LnByb3RvdHlwZSk7ICAvLyByZXN0b3JlIHByb3RvdHlwZSBjaGFpblxuICAgIHRoaXMubmFtZSA9IG5ldy50YXJnZXQubmFtZTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgSW52YWxpZENvbmZpZ0ZpZWxkIGV4dGVuZHMgU2hhZG93c29ja3NDb25maWdFcnJvciB7fVxuXG5leHBvcnQgY2xhc3MgSW52YWxpZFVyaSBleHRlbmRzIFNoYWRvd3NvY2tzQ29uZmlnRXJyb3Ige31cblxuLy8gU2VsZi12YWxpZGF0aW5nL25vcm1hbGl6aW5nIGNvbmZpZyBkYXRhIHR5cGVzIGltcGxlbWVudCB0aGlzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIGludGVyZmFjZS5cbi8vIENvbnN0cnVjdG9ycyB0YWtlIHNvbWUgZGF0YSwgdmFsaWRhdGUsIG5vcm1hbGl6ZSwgYW5kIHN0b3JlIGlmIHZhbGlkLCBvciB0aHJvdyBvdGhlcndpc2UuXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgVmFsaWRhdGVkQ29uZmlnRmllbGQge31cblxuZnVuY3Rpb24gdGhyb3dFcnJvckZvckludmFsaWRGaWVsZChuYW1lOiBzdHJpbmcsIHZhbHVlOiB7fSwgcmVhc29uPzogc3RyaW5nKSB7XG4gIHRocm93IG5ldyBJbnZhbGlkQ29uZmlnRmllbGQoYEludmFsaWQgJHtuYW1lfTogJHt2YWx1ZX0gJHtyZWFzb24gfHwgJyd9YCk7XG59XG5cbmV4cG9ydCBjbGFzcyBIb3N0IGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgc3RhdGljIElQVjRfUEFUVEVSTiA9IC9eKD86WzAtOV17MSwzfVxcLil7M31bMC05XXsxLDN9JC87XG4gIHB1YmxpYyBzdGF0aWMgSVBWNl9QQVRURVJOID0gL14oPzpbQS1GMC05XXsxLDR9Oil7N31bQS1GMC05XXsxLDR9JC9pO1xuICBwdWJsaWMgc3RhdGljIEhPU1ROQU1FX1BBVFRFUk4gPSAvXltBLXowLTldK1tBLXowLTlfLi1dKiQvO1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuICBwdWJsaWMgcmVhZG9ubHkgaXNJUHY0OiBib29sZWFuO1xuICBwdWJsaWMgcmVhZG9ubHkgaXNJUHY2OiBib29sZWFuO1xuICBwdWJsaWMgcmVhZG9ubHkgaXNIb3N0bmFtZTogYm9vbGVhbjtcblxuICBjb25zdHJ1Y3Rvcihob3N0OiBIb3N0IHwgc3RyaW5nKSB7XG4gICAgc3VwZXIoKTtcbiAgICBpZiAoIWhvc3QpIHtcbiAgICAgIHRocm93RXJyb3JGb3JJbnZhbGlkRmllbGQoJ2hvc3QnLCBob3N0KTtcbiAgICB9XG4gICAgaWYgKGhvc3QgaW5zdGFuY2VvZiBIb3N0KSB7XG4gICAgICBob3N0ID0gaG9zdC5kYXRhO1xuICAgIH1cbiAgICBob3N0ID0gcHVueWNvZGUudG9BU0NJSShob3N0KSBhcyBzdHJpbmc7XG4gICAgdGhpcy5pc0lQdjQgPSBIb3N0LklQVjRfUEFUVEVSTi50ZXN0KGhvc3QpO1xuICAgIHRoaXMuaXNJUHY2ID0gdGhpcy5pc0lQdjQgPyBmYWxzZSA6IEhvc3QuSVBWNl9QQVRURVJOLnRlc3QoaG9zdCk7XG4gICAgdGhpcy5pc0hvc3RuYW1lID0gdGhpcy5pc0lQdjQgfHwgdGhpcy5pc0lQdjYgPyBmYWxzZSA6IEhvc3QuSE9TVE5BTUVfUEFUVEVSTi50ZXN0KGhvc3QpO1xuICAgIGlmICghKHRoaXMuaXNJUHY0IHx8IHRoaXMuaXNJUHY2IHx8IHRoaXMuaXNIb3N0bmFtZSkpIHtcbiAgICAgIHRocm93RXJyb3JGb3JJbnZhbGlkRmllbGQoJ2hvc3QnLCBob3N0KTtcbiAgICB9XG4gICAgdGhpcy5kYXRhID0gaG9zdDtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgUG9ydCBleHRlbmRzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHtcbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBQQVRURVJOID0gL15bMC05XXsxLDV9JC87XG4gIHB1YmxpYyByZWFkb25seSBkYXRhOiBudW1iZXI7XG5cbiAgY29uc3RydWN0b3IocG9ydDogUG9ydCB8IHN0cmluZyB8IG51bWJlcikge1xuICAgIHN1cGVyKCk7XG4gICAgaWYgKHBvcnQgaW5zdGFuY2VvZiBQb3J0KSB7XG4gICAgICBwb3J0ID0gcG9ydC5kYXRhO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIHBvcnQgPT09ICdudW1iZXInKSB7XG4gICAgICAvLyBTdHJpbmdpZnkgaW4gY2FzZSBuZWdhdGl2ZSBvciBmbG9hdGluZyBwb2ludCAtPiB0aGUgcmVnZXggdGVzdCBiZWxvdyB3aWxsIGNhdGNoLlxuICAgICAgcG9ydCA9IHBvcnQudG9TdHJpbmcoKTtcbiAgICB9XG4gICAgaWYgKCFQb3J0LlBBVFRFUk4udGVzdChwb3J0KSkge1xuICAgICAgdGhyb3dFcnJvckZvckludmFsaWRGaWVsZCgncG9ydCcsIHBvcnQpO1xuICAgIH1cbiAgICAvLyBDb3VsZCBleGNlZWQgdGhlIG1heGltdW0gcG9ydCBudW1iZXIsIHNvIGNvbnZlcnQgdG8gTnVtYmVyIHRvIGNoZWNrLiBDb3VsZCBhbHNvIGhhdmUgbGVhZGluZ1xuICAgIC8vIHplcm9zLiBDb252ZXJ0aW5nIHRvIE51bWJlciBkcm9wcyB0aG9zZSwgc28gd2UgZ2V0IG5vcm1hbGl6YXRpb24gZm9yIGZyZWUuIDopXG4gICAgcG9ydCA9IE51bWJlcihwb3J0KTtcbiAgICBpZiAocG9ydCA+IDY1NTM1KSB7XG4gICAgICB0aHJvd0Vycm9yRm9ySW52YWxpZEZpZWxkKCdwb3J0JywgcG9ydCk7XG4gICAgfVxuICAgIHRoaXMuZGF0YSA9IHBvcnQ7XG4gIH1cbn1cblxuLy8gQSBtZXRob2QgdmFsdWUgbXVzdCBleGFjdGx5IG1hdGNoIGFuIGVsZW1lbnQgaW4gdGhlIHNldCBvZiBrbm93biBjaXBoZXJzLlxuLy8gcmVmOiBodHRwczovL2dpdGh1Yi5jb20vc2hhZG93c29ja3Mvc2hhZG93c29ja3MtbGliZXYvYmxvYi8xMGEyZDNlMy9jb21wbGV0aW9ucy9iYXNoL3NzLXJlZGlyI0w1XG5leHBvcnQgY29uc3QgTUVUSE9EUyA9IG5ldyBTZXQoW1xuICAncmM0LW1kNScsXG4gICdhZXMtMTI4LWdjbScsXG4gICdhZXMtMTkyLWdjbScsXG4gICdhZXMtMjU2LWdjbScsXG4gICdhZXMtMTI4LWNmYicsXG4gICdhZXMtMTkyLWNmYicsXG4gICdhZXMtMjU2LWNmYicsXG4gICdhZXMtMTI4LWN0cicsXG4gICdhZXMtMTkyLWN0cicsXG4gICdhZXMtMjU2LWN0cicsXG4gICdjYW1lbGxpYS0xMjgtY2ZiJyxcbiAgJ2NhbWVsbGlhLTE5Mi1jZmInLFxuICAnY2FtZWxsaWEtMjU2LWNmYicsXG4gICdiZi1jZmInLFxuICAnY2hhY2hhMjAtaWV0Zi1wb2x5MTMwNScsXG4gICdzYWxzYTIwJyxcbiAgJ2NoYWNoYTIwJyxcbiAgJ2NoYWNoYTIwLWlldGYnLFxuICAneGNoYWNoYTIwLWlldGYtcG9seTEzMDUnLFxuXSk7XG5cbmV4cG9ydCBjbGFzcyBNZXRob2QgZXh0ZW5kcyBWYWxpZGF0ZWRDb25maWdGaWVsZCB7XG4gIHB1YmxpYyByZWFkb25seSBkYXRhOiBzdHJpbmc7XG4gIGNvbnN0cnVjdG9yKG1ldGhvZDogTWV0aG9kIHwgc3RyaW5nKSB7XG4gICAgc3VwZXIoKTtcbiAgICBpZiAobWV0aG9kIGluc3RhbmNlb2YgTWV0aG9kKSB7XG4gICAgICBtZXRob2QgPSBtZXRob2QuZGF0YTtcbiAgICB9XG4gICAgaWYgKCFNRVRIT0RTLmhhcyhtZXRob2QpKSB7XG4gICAgICB0aHJvd0Vycm9yRm9ySW52YWxpZEZpZWxkKCdtZXRob2QnLCBtZXRob2QpO1xuICAgIH1cbiAgICB0aGlzLmRhdGEgPSBtZXRob2Q7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFBhc3N3b3JkIGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuXG4gIGNvbnN0cnVjdG9yKHBhc3N3b3JkOiBQYXNzd29yZCB8IHN0cmluZykge1xuICAgIHN1cGVyKCk7XG4gICAgdGhpcy5kYXRhID0gcGFzc3dvcmQgaW5zdGFuY2VvZiBQYXNzd29yZCA/IHBhc3N3b3JkLmRhdGEgOiBwYXNzd29yZDtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgVGFnIGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuXG4gIGNvbnN0cnVjdG9yKHRhZzogVGFnIHwgc3RyaW5nID0gJycpIHtcbiAgICBzdXBlcigpO1xuICAgIHRoaXMuZGF0YSA9IHRhZyBpbnN0YW5jZW9mIFRhZyA/IHRhZy5kYXRhIDogdGFnO1xuICB9XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ29uZmlnIHtcbiAgaG9zdDogSG9zdDtcbiAgcG9ydDogUG9ydDtcbiAgbWV0aG9kOiBNZXRob2Q7XG4gIHBhc3N3b3JkOiBQYXNzd29yZDtcbiAgdGFnOiBUYWc7XG4gIC8vIEFueSBhZGRpdGlvbmFsIGNvbmZpZ3VyYXRpb24gKGUuZy4gYHRpbWVvdXRgLCBTSVAwMDMgYHBsdWdpbmAsIGV0Yy4pIG1heSBiZSBzdG9yZWQgaGVyZS5cbiAgZXh0cmE6IHtba2V5OiBzdHJpbmddOiBzdHJpbmd9O1xufVxuXG4vLyB0c2xpbnQ6ZGlzYWJsZS1uZXh0LWxpbmU6bm8tYW55XG5leHBvcnQgZnVuY3Rpb24gbWFrZUNvbmZpZyhpbnB1dDoge1trZXk6IHN0cmluZ106IGFueX0pOiBDb25maWcge1xuICAvLyBVc2UgXCIhXCIgZm9yIHRoZSByZXF1aXJlZCBmaWVsZHMgdG8gdGVsbCB0c2MgdGhhdCB3ZSBoYW5kbGUgdW5kZWZpbmVkIGluIHRoZVxuICAvLyBWYWxpZGF0ZWRDb25maWdGaWVsZHMgd2UgY2FsbDsgdHNjIGNhbid0IGZpZ3VyZSB0aGF0IG91dCBvdGhlcndpc2UuXG4gIGNvbnN0IGNvbmZpZyA9IHtcbiAgICBob3N0OiBuZXcgSG9zdChpbnB1dC5ob3N0ISksXG4gICAgcG9ydDogbmV3IFBvcnQoaW5wdXQucG9ydCEpLFxuICAgIG1ldGhvZDogbmV3IE1ldGhvZChpbnB1dC5tZXRob2QhKSxcbiAgICBwYXNzd29yZDogbmV3IFBhc3N3b3JkKGlucHV0LnBhc3N3b3JkISksXG4gICAgdGFnOiBuZXcgVGFnKGlucHV0LnRhZyksICAvLyBpbnB1dC50YWcgbWlnaHQgYmUgdW5kZWZpbmVkIGJ1dCBUYWcoKSBoYW5kbGVzIHRoYXQgZmluZS5cbiAgICBleHRyYToge30gYXMge1trZXk6IHN0cmluZ106IHN0cmluZ30sXG4gIH07XG4gIC8vIFB1dCBhbnkgcmVtYWluaW5nIGZpZWxkcyBpbiBgaW5wdXRgIGludG8gYGNvbmZpZy5leHRyYWAuXG4gIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKGlucHV0KSkge1xuICAgIGlmICghL14oaG9zdHxwb3J0fG1ldGhvZHxwYXNzd29yZHx0YWcpJC8udGVzdChrZXkpKSB7XG4gICAgICBjb25maWcuZXh0cmFba2V5XSA9IGlucHV0W2tleV0gJiYgaW5wdXRba2V5XS50b1N0cmluZygpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gY29uZmlnO1xufVxuXG5leHBvcnQgY29uc3QgU0hBRE9XU09DS1NfVVJJID0ge1xuICBQUk9UT0NPTDogJ3NzOicsXG5cbiAgZ2V0VXJpRm9ybWF0dGVkSG9zdDogKGhvc3Q6IEhvc3QpID0+IHtcbiAgICByZXR1cm4gaG9zdC5pc0lQdjYgPyBgWyR7aG9zdC5kYXRhfV1gIDogaG9zdC5kYXRhO1xuICB9LFxuXG4gIGdldEhhc2g6ICh0YWc6IFRhZykgPT4ge1xuICAgIHJldHVybiB0YWcuZGF0YSA/IGAjJHtlbmNvZGVVUklDb21wb25lbnQodGFnLmRhdGEpfWAgOiAnJztcbiAgfSxcblxuICB2YWxpZGF0ZVByb3RvY29sOiAodXJpOiBzdHJpbmcpID0+IHtcbiAgICBpZiAoIXVyaS5zdGFydHNXaXRoKFNIQURPV1NPQ0tTX1VSSS5QUk9UT0NPTCkpIHtcbiAgICAgIHRocm93IG5ldyBJbnZhbGlkVXJpKGBVUkkgbXVzdCBzdGFydCB3aXRoIFwiJHtTSEFET1dTT0NLU19VUkkuUFJPVE9DT0x9XCJgKTtcbiAgICB9XG4gIH0sXG5cbiAgcGFyc2U6ICh1cmk6IHN0cmluZyk6IENvbmZpZyA9PiB7XG4gICAgbGV0IGVycm9yOiBFcnJvciB8IHVuZGVmaW5lZDtcbiAgICBmb3IgKGNvbnN0IHVyaVR5cGUgb2YgW1NJUDAwMl9VUkksIExFR0FDWV9CQVNFNjRfVVJJXSkge1xuICAgICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIHVyaVR5cGUucGFyc2UodXJpKTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgZXJyb3IgPSBlO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAoIShlcnJvciBpbnN0YW5jZW9mIEludmFsaWRVcmkpKSB7XG4gICAgICBjb25zdCBvcmlnaW5hbEVycm9yTmFtZSA9IGVycm9yIS5uYW1lISB8fCAnKFVubmFtZWQgRXJyb3IpJztcbiAgICAgIGNvbnN0IG9yaWdpbmFsRXJyb3JNZXNzYWdlID0gZXJyb3IhLm1lc3NhZ2UhIHx8ICcobm8gZXJyb3IgbWVzc2FnZSBwcm92aWRlZCknO1xuICAgICAgY29uc3Qgb3JpZ2luYWxFcnJvclN0cmluZyA9IGAke29yaWdpbmFsRXJyb3JOYW1lfTogJHtvcmlnaW5hbEVycm9yTWVzc2FnZX1gO1xuICAgICAgY29uc3QgbmV3RXJyb3JNZXNzYWdlID0gYEludmFsaWQgaW5wdXQ6ICR7b3JpZ2luYWxFcnJvclN0cmluZ31gO1xuICAgICAgZXJyb3IgPSBuZXcgSW52YWxpZFVyaShuZXdFcnJvck1lc3NhZ2UpO1xuICAgIH1cbiAgICB0aHJvdyBlcnJvcjtcbiAgfSxcbn07XG5cbi8vIFJlZjogaHR0cHM6Ly9zaGFkb3dzb2Nrcy5vcmcvZW4vY29uZmlnL3F1aWNrLWd1aWRlLmh0bWxcbmV4cG9ydCBjb25zdCBMRUdBQ1lfQkFTRTY0X1VSSSA9IHtcbiAgcGFyc2U6ICh1cmk6IHN0cmluZyk6IENvbmZpZyA9PiB7XG4gICAgU0hBRE9XU09DS1NfVVJJLnZhbGlkYXRlUHJvdG9jb2wodXJpKTtcbiAgICBjb25zdCBoYXNoSW5kZXggPSB1cmkuaW5kZXhPZignIycpO1xuICAgIGNvbnN0IGhhc1RhZyA9IGhhc2hJbmRleCAhPT0gLTE7XG4gICAgY29uc3QgYjY0RW5kSW5kZXggPSBoYXNUYWcgPyBoYXNoSW5kZXggOiB1cmkubGVuZ3RoO1xuICAgIGNvbnN0IHRhZ1N0YXJ0SW5kZXggPSBoYXNUYWcgPyBoYXNoSW5kZXggKyAxIDogdXJpLmxlbmd0aDtcbiAgICBjb25zdCB0YWcgPSBuZXcgVGFnKGRlY29kZVVSSUNvbXBvbmVudCh1cmkuc3Vic3RyaW5nKHRhZ1N0YXJ0SW5kZXgpKSk7XG4gICAgY29uc3QgYjY0RW5jb2RlZERhdGEgPSB1cmkuc3Vic3RyaW5nKCdzczovLycubGVuZ3RoLCBiNjRFbmRJbmRleCk7XG4gICAgY29uc3QgYjY0RGVjb2RlZERhdGEgPSBiNjREZWNvZGUoYjY0RW5jb2RlZERhdGEpO1xuICAgIGNvbnN0IGF0U2lnbkluZGV4ID0gYjY0RGVjb2RlZERhdGEubGFzdEluZGV4T2YoJ0AnKTtcbiAgICBpZiAoYXRTaWduSW5kZXggPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgTWlzc2luZyBcIkBcImApO1xuICAgIH1cbiAgICBjb25zdCBtZXRob2RBbmRQYXNzd29yZCA9IGI2NERlY29kZWREYXRhLnN1YnN0cmluZygwLCBhdFNpZ25JbmRleCk7XG4gICAgY29uc3QgbWV0aG9kRW5kSW5kZXggPSBtZXRob2RBbmRQYXNzd29yZC5pbmRleE9mKCc6Jyk7XG4gICAgaWYgKG1ldGhvZEVuZEluZGV4ID09PSAtMSkge1xuICAgICAgdGhyb3cgbmV3IEludmFsaWRVcmkoYE1pc3NpbmcgcGFzc3dvcmRgKTtcbiAgICB9XG4gICAgY29uc3QgbWV0aG9kU3RyaW5nID0gbWV0aG9kQW5kUGFzc3dvcmQuc3Vic3RyaW5nKDAsIG1ldGhvZEVuZEluZGV4KTtcbiAgICBjb25zdCBtZXRob2QgPSBuZXcgTWV0aG9kKG1ldGhvZFN0cmluZyk7XG4gICAgY29uc3QgcGFzc3dvcmRTdGFydEluZGV4ID0gbWV0aG9kRW5kSW5kZXggKyAxO1xuICAgIGNvbnN0IHBhc3N3b3JkU3RyaW5nID0gbWV0aG9kQW5kUGFzc3dvcmQuc3Vic3RyaW5nKHBhc3N3b3JkU3RhcnRJbmRleCk7XG4gICAgY29uc3QgcGFzc3dvcmQgPSBuZXcgUGFzc3dvcmQocGFzc3dvcmRTdHJpbmcpO1xuICAgIGNvbnN0IGhvc3RTdGFydEluZGV4ID0gYXRTaWduSW5kZXggKyAxO1xuICAgIGNvbnN0IGhvc3RBbmRQb3J0ID0gYjY0RGVjb2RlZERhdGEuc3Vic3RyaW5nKGhvc3RTdGFydEluZGV4KTtcbiAgICBjb25zdCBob3N0RW5kSW5kZXggPSBob3N0QW5kUG9ydC5sYXN0SW5kZXhPZignOicpO1xuICAgIGlmIChob3N0RW5kSW5kZXggPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgTWlzc2luZyBwb3J0YCk7XG4gICAgfVxuICAgIGNvbnN0IHVyaUZvcm1hdHRlZEhvc3QgPSBob3N0QW5kUG9ydC5zdWJzdHJpbmcoMCwgaG9zdEVuZEluZGV4KTtcbiAgICBsZXQgaG9zdDogSG9zdDtcbiAgICB0cnkge1xuICAgICAgaG9zdCA9IG5ldyBIb3N0KHVyaUZvcm1hdHRlZEhvc3QpO1xuICAgIH0gY2F0Y2ggKF8pIHtcbiAgICAgIC8vIENvdWxkIGJlIElQdjYgaG9zdCBmb3JtYXR0ZWQgd2l0aCBzdXJyb3VuZGluZyBicmFja2V0cywgc28gdHJ5IHN0cmlwcGluZyBmaXJzdCBhbmQgbGFzdFxuICAgICAgLy8gY2hhcmFjdGVycy4gSWYgdGhpcyB0aHJvd3MsIGdpdmUgdXAgYW5kIGxldCB0aGUgZXhjZXB0aW9uIHByb3BhZ2F0ZS5cbiAgICAgIGhvc3QgPSBuZXcgSG9zdCh1cmlGb3JtYXR0ZWRIb3N0LnN1YnN0cmluZygxLCB1cmlGb3JtYXR0ZWRIb3N0Lmxlbmd0aCAtIDEpKTtcbiAgICB9XG4gICAgY29uc3QgcG9ydFN0YXJ0SW5kZXggPSBob3N0RW5kSW5kZXggKyAxO1xuICAgIGNvbnN0IHBvcnRTdHJpbmcgPSBob3N0QW5kUG9ydC5zdWJzdHJpbmcocG9ydFN0YXJ0SW5kZXgpO1xuICAgIGNvbnN0IHBvcnQgPSBuZXcgUG9ydChwb3J0U3RyaW5nKTtcbiAgICBjb25zdCBleHRyYSA9IHt9IGFzIHtba2V5OiBzdHJpbmddOiBzdHJpbmd9OyAgLy8gZW1wdHkgYmVjYXVzZSBMZWdhY3lCYXNlNjRVcmkgY2FuJ3QgaG9sZCBleHRyYVxuICAgIHJldHVybiB7bWV0aG9kLCBwYXNzd29yZCwgaG9zdCwgcG9ydCwgdGFnLCBleHRyYX07XG4gIH0sXG5cbiAgc3RyaW5naWZ5OiAoY29uZmlnOiBDb25maWcpID0+IHtcbiAgICBjb25zdCB7aG9zdCwgcG9ydCwgbWV0aG9kLCBwYXNzd29yZCwgdGFnfSA9IGNvbmZpZztcbiAgICBjb25zdCBoYXNoID0gU0hBRE9XU09DS1NfVVJJLmdldEhhc2godGFnKTtcbiAgICBsZXQgYjY0RW5jb2RlZERhdGEgPSBiNjRFbmNvZGUoYCR7bWV0aG9kLmRhdGF9OiR7cGFzc3dvcmQuZGF0YX1AJHtob3N0LmRhdGF9OiR7cG9ydC5kYXRhfWApO1xuICAgIGNvbnN0IGRhdGFMZW5ndGggPSBiNjRFbmNvZGVkRGF0YS5sZW5ndGg7XG4gICAgbGV0IHBhZGRpbmdMZW5ndGggPSAwO1xuICAgIGZvciAoOyBiNjRFbmNvZGVkRGF0YVtkYXRhTGVuZ3RoIC0gMSAtIHBhZGRpbmdMZW5ndGhdID09PSAnPSc7IHBhZGRpbmdMZW5ndGgrKyk7XG4gICAgYjY0RW5jb2RlZERhdGEgPSBwYWRkaW5nTGVuZ3RoID09PSAwID8gYjY0RW5jb2RlZERhdGEgOlxuICAgICAgICBiNjRFbmNvZGVkRGF0YS5zdWJzdHJpbmcoMCwgZGF0YUxlbmd0aCAtIHBhZGRpbmdMZW5ndGgpO1xuICAgIHJldHVybiBgc3M6Ly8ke2I2NEVuY29kZWREYXRhfSR7aGFzaH1gO1xuICB9LFxufTtcblxuLy8gUmVmOiBodHRwczovL3NoYWRvd3NvY2tzLm9yZy9lbi9zcGVjL1NJUDAwMi1VUkktU2NoZW1lLmh0bWxcbmV4cG9ydCBjb25zdCBTSVAwMDJfVVJJID0ge1xuICBwYXJzZTogKHVyaTogc3RyaW5nKTogQ29uZmlnID0+IHtcbiAgICBTSEFET1dTT0NLU19VUkkudmFsaWRhdGVQcm90b2NvbCh1cmkpO1xuICAgIC8vIENhbiB1c2UgYnVpbHQtaW4gVVJMIHBhcnNlciBmb3IgZXhwZWRpZW5jZS4gSnVzdCBoYXZlIHRvIHJlcGxhY2UgXCJzc1wiIHdpdGggXCJodHRwXCIgdG8gZW5zdXJlXG4gICAgLy8gY29ycmVjdCByZXN1bHRzLCBvdGhlcndpc2UgYnJvd3NlcnMgbGlrZSBTYWZhcmkgZmFpbCB0byBwYXJzZSBpdC5cbiAgICBjb25zdCBpbnB1dEZvclVybFBhcnNlciA9IGBodHRwJHt1cmkuc3Vic3RyaW5nKDIpfWA7XG4gICAgLy8gVGhlIGJ1aWx0LWluIFVSTCBwYXJzZXIgdGhyb3dzIGFzIGRlc2lyZWQgd2hlbiBnaXZlbiBVUklzIHdpdGggaW52YWxpZCBzeW50YXguXG4gICAgY29uc3QgdXJsUGFyc2VyUmVzdWx0ID0gbmV3IFVSTChpbnB1dEZvclVybFBhcnNlcik7XG4gICAgY29uc3QgdXJpRm9ybWF0dGVkSG9zdCA9IHVybFBhcnNlclJlc3VsdC5ob3N0bmFtZTtcbiAgICAvLyBVUkktZm9ybWF0dGVkIElQdjYgaG9zdG5hbWVzIGhhdmUgc3Vycm91bmRpbmcgYnJhY2tldHMuXG4gICAgY29uc3QgbGFzdCA9IHVyaUZvcm1hdHRlZEhvc3QubGVuZ3RoIC0gMTtcbiAgICBjb25zdCBicmFja2V0cyA9IHVyaUZvcm1hdHRlZEhvc3RbMF0gPT09ICdbJyAmJiB1cmlGb3JtYXR0ZWRIb3N0W2xhc3RdID09PSAnXSc7XG4gICAgY29uc3QgaG9zdFN0cmluZyA9IGJyYWNrZXRzID8gdXJpRm9ybWF0dGVkSG9zdC5zdWJzdHJpbmcoMSwgbGFzdCkgOiB1cmlGb3JtYXR0ZWRIb3N0O1xuICAgIGNvbnN0IGhvc3QgPSBuZXcgSG9zdChob3N0U3RyaW5nKTtcbiAgICBsZXQgcGFyc2VkUG9ydCA9IHVybFBhcnNlclJlc3VsdC5wb3J0O1xuICAgIGlmICghcGFyc2VkUG9ydCAmJiB1cmkubWF0Y2goLzo4MCgkfFxcLykvZykpIHtcbiAgICAgIC8vIFRoZSBkZWZhdWx0IFVSTCBwYXJzZXIgZmFpbHMgdG8gcmVjb2duaXplIHRoZSBkZWZhdWx0IHBvcnQgKDgwKSB3aGVuIHRoZSBVUkkgYmVpbmcgcGFyc2VkXG4gICAgICAvLyBpcyBIVFRQLiBDaGVjayBpZiB0aGUgcG9ydCBpcyBwcmVzZW50IGF0IHRoZSBlbmQgb2YgdGhlIHN0cmluZyBvciBiZWZvcmUgdGhlIHBhcmFtZXRlcnMuXG4gICAgICBwYXJzZWRQb3J0ID0gODA7XG4gICAgfVxuICAgIGNvbnN0IHBvcnQgPSBuZXcgUG9ydChwYXJzZWRQb3J0KTtcbiAgICBjb25zdCB0YWcgPSBuZXcgVGFnKGRlY29kZVVSSUNvbXBvbmVudCh1cmxQYXJzZXJSZXN1bHQuaGFzaC5zdWJzdHJpbmcoMSkpKTtcbiAgICBjb25zdCBiNjRFbmNvZGVkVXNlckluZm8gPSB1cmxQYXJzZXJSZXN1bHQudXNlcm5hbWUucmVwbGFjZSgvJTNEL2csICc9Jyk7XG4gICAgLy8gYmFzZTY0LmRlY29kZSB0aHJvd3MgYXMgZGVzaXJlZCB3aGVuIGdpdmVuIGludmFsaWQgYmFzZTY0IGlucHV0LlxuICAgIGNvbnN0IGI2NERlY29kZWRVc2VySW5mbyA9IGI2NERlY29kZShiNjRFbmNvZGVkVXNlckluZm8pO1xuICAgIGNvbnN0IGNvbG9uSWR4ID0gYjY0RGVjb2RlZFVzZXJJbmZvLmluZGV4T2YoJzonKTtcbiAgICBpZiAoY29sb25JZHggPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgTWlzc2luZyBwYXNzd29yZGApO1xuICAgIH1cbiAgICBjb25zdCBtZXRob2RTdHJpbmcgPSBiNjREZWNvZGVkVXNlckluZm8uc3Vic3RyaW5nKDAsIGNvbG9uSWR4KTtcbiAgICBjb25zdCBtZXRob2QgPSBuZXcgTWV0aG9kKG1ldGhvZFN0cmluZyk7XG4gICAgY29uc3QgcGFzc3dvcmRTdHJpbmcgPSBiNjREZWNvZGVkVXNlckluZm8uc3Vic3RyaW5nKGNvbG9uSWR4ICsgMSk7XG4gICAgY29uc3QgcGFzc3dvcmQgPSBuZXcgUGFzc3dvcmQocGFzc3dvcmRTdHJpbmcpO1xuICAgIGNvbnN0IHF1ZXJ5UGFyYW1zID0gdXJsUGFyc2VyUmVzdWx0LnNlYXJjaC5zdWJzdHJpbmcoMSkuc3BsaXQoJyYnKTtcbiAgICBjb25zdCBleHRyYSA9IHt9IGFzIHtba2V5OiBzdHJpbmddOiBzdHJpbmd9O1xuICAgIGZvciAoY29uc3QgcGFpciBvZiBxdWVyeVBhcmFtcykge1xuICAgICAgY29uc3QgW2tleSwgdmFsdWVdID0gcGFpci5zcGxpdCgnPScsIDIpO1xuICAgICAgaWYgKCFrZXkpIGNvbnRpbnVlO1xuICAgICAgZXh0cmFba2V5XSA9IGRlY29kZVVSSUNvbXBvbmVudCh2YWx1ZSB8fCAnJyk7XG4gICAgfVxuICAgIHJldHVybiB7bWV0aG9kLCBwYXNzd29yZCwgaG9zdCwgcG9ydCwgdGFnLCBleHRyYX07XG4gIH0sXG5cbiAgc3RyaW5naWZ5OiAoY29uZmlnOiBDb25maWcpID0+IHtcbiAgICBjb25zdCB7aG9zdCwgcG9ydCwgbWV0aG9kLCBwYXNzd29yZCwgdGFnLCBleHRyYX0gPSBjb25maWc7XG4gICAgY29uc3QgdXNlckluZm8gPSBiNjRFbmNvZGUoYCR7bWV0aG9kLmRhdGF9OiR7cGFzc3dvcmQuZGF0YX1gKTtcbiAgICBjb25zdCB1cmlIb3N0ID0gU0hBRE9XU09DS1NfVVJJLmdldFVyaUZvcm1hdHRlZEhvc3QoaG9zdCk7XG4gICAgY29uc3QgaGFzaCA9IFNIQURPV1NPQ0tTX1VSSS5nZXRIYXNoKHRhZyk7XG4gICAgbGV0IHF1ZXJ5U3RyaW5nID0gJyc7XG4gICAgZm9yIChjb25zdCBrZXkgaW4gZXh0cmEpIHtcbiAgICAgIGlmICgha2V5KSBjb250aW51ZTtcbiAgICAgIHF1ZXJ5U3RyaW5nICs9IChxdWVyeVN0cmluZyA/ICcmJyA6ICc/JykgKyBgJHtrZXl9PSR7ZW5jb2RlVVJJQ29tcG9uZW50KGV4dHJhW2tleV0pfWA7XG4gICAgfVxuICAgIHJldHVybiBgc3M6Ly8ke3VzZXJJbmZvfUAke3VyaUhvc3R9OiR7cG9ydC5kYXRhfS8ke3F1ZXJ5U3RyaW5nfSR7aGFzaH1gO1xuICB9LFxufTtcbiIsIi8qISBodHRwOi8vbXRocy5iZS9iYXNlNjQgdjAuMS4wIGJ5IEBtYXRoaWFzIHwgTUlUIGxpY2Vuc2UgKi9cbjsoZnVuY3Rpb24ocm9vdCkge1xuXG5cdC8vIERldGVjdCBmcmVlIHZhcmlhYmxlcyBgZXhwb3J0c2AuXG5cdHZhciBmcmVlRXhwb3J0cyA9IHR5cGVvZiBleHBvcnRzID09ICdvYmplY3QnICYmIGV4cG9ydHM7XG5cblx0Ly8gRGV0ZWN0IGZyZWUgdmFyaWFibGUgYG1vZHVsZWAuXG5cdHZhciBmcmVlTW9kdWxlID0gdHlwZW9mIG1vZHVsZSA9PSAnb2JqZWN0JyAmJiBtb2R1bGUgJiZcblx0XHRtb2R1bGUuZXhwb3J0cyA9PSBmcmVlRXhwb3J0cyAmJiBtb2R1bGU7XG5cblx0Ly8gRGV0ZWN0IGZyZWUgdmFyaWFibGUgYGdsb2JhbGAsIGZyb20gTm9kZS5qcyBvciBCcm93c2VyaWZpZWQgY29kZSwgYW5kIHVzZVxuXHQvLyBpdCBhcyBgcm9vdGAuXG5cdHZhciBmcmVlR2xvYmFsID0gdHlwZW9mIGdsb2JhbCA9PSAnb2JqZWN0JyAmJiBnbG9iYWw7XG5cdGlmIChmcmVlR2xvYmFsLmdsb2JhbCA9PT0gZnJlZUdsb2JhbCB8fCBmcmVlR2xvYmFsLndpbmRvdyA9PT0gZnJlZUdsb2JhbCkge1xuXHRcdHJvb3QgPSBmcmVlR2xvYmFsO1xuXHR9XG5cblx0LyotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSovXG5cblx0dmFyIEludmFsaWRDaGFyYWN0ZXJFcnJvciA9IGZ1bmN0aW9uKG1lc3NhZ2UpIHtcblx0XHR0aGlzLm1lc3NhZ2UgPSBtZXNzYWdlO1xuXHR9O1xuXHRJbnZhbGlkQ2hhcmFjdGVyRXJyb3IucHJvdG90eXBlID0gbmV3IEVycm9yO1xuXHRJbnZhbGlkQ2hhcmFjdGVyRXJyb3IucHJvdG90eXBlLm5hbWUgPSAnSW52YWxpZENoYXJhY3RlckVycm9yJztcblxuXHR2YXIgZXJyb3IgPSBmdW5jdGlvbihtZXNzYWdlKSB7XG5cdFx0Ly8gTm90ZTogdGhlIGVycm9yIG1lc3NhZ2VzIHVzZWQgdGhyb3VnaG91dCB0aGlzIGZpbGUgbWF0Y2ggdGhvc2UgdXNlZCBieVxuXHRcdC8vIHRoZSBuYXRpdmUgYGF0b2JgL2BidG9hYCBpbXBsZW1lbnRhdGlvbiBpbiBDaHJvbWl1bS5cblx0XHR0aHJvdyBuZXcgSW52YWxpZENoYXJhY3RlckVycm9yKG1lc3NhZ2UpO1xuXHR9O1xuXG5cdHZhciBUQUJMRSA9ICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvJztcblx0Ly8gaHR0cDovL3doYXR3Zy5vcmcvaHRtbC9jb21tb24tbWljcm9zeW50YXhlcy5odG1sI3NwYWNlLWNoYXJhY3RlclxuXHR2YXIgUkVHRVhfU1BBQ0VfQ0hBUkFDVEVSUyA9IC9bXFx0XFxuXFxmXFxyIF0vZztcblxuXHQvLyBgZGVjb2RlYCBpcyBkZXNpZ25lZCB0byBiZSBmdWxseSBjb21wYXRpYmxlIHdpdGggYGF0b2JgIGFzIGRlc2NyaWJlZCBpbiB0aGVcblx0Ly8gSFRNTCBTdGFuZGFyZC4gaHR0cDovL3doYXR3Zy5vcmcvaHRtbC93ZWJhcHBhcGlzLmh0bWwjZG9tLXdpbmRvd2Jhc2U2NC1hdG9iXG5cdC8vIFRoZSBvcHRpbWl6ZWQgYmFzZTY0LWRlY29kaW5nIGFsZ29yaXRobSB1c2VkIGlzIGJhc2VkIG9uIEBhdGvigJlzIGV4Y2VsbGVudFxuXHQvLyBpbXBsZW1lbnRhdGlvbi4gaHR0cHM6Ly9naXN0LmdpdGh1Yi5jb20vYXRrLzEwMjAzOTZcblx0dmFyIGRlY29kZSA9IGZ1bmN0aW9uKGlucHV0KSB7XG5cdFx0aW5wdXQgPSBTdHJpbmcoaW5wdXQpXG5cdFx0XHQucmVwbGFjZShSRUdFWF9TUEFDRV9DSEFSQUNURVJTLCAnJyk7XG5cdFx0dmFyIGxlbmd0aCA9IGlucHV0Lmxlbmd0aDtcblx0XHRpZiAobGVuZ3RoICUgNCA9PSAwKSB7XG5cdFx0XHRpbnB1dCA9IGlucHV0LnJlcGxhY2UoLz09PyQvLCAnJyk7XG5cdFx0XHRsZW5ndGggPSBpbnB1dC5sZW5ndGg7XG5cdFx0fVxuXHRcdGlmIChcblx0XHRcdGxlbmd0aCAlIDQgPT0gMSB8fFxuXHRcdFx0Ly8gaHR0cDovL3doYXR3Zy5vcmcvQyNhbHBoYW51bWVyaWMtYXNjaWktY2hhcmFjdGVyc1xuXHRcdFx0L1teK2EtekEtWjAtOS9dLy50ZXN0KGlucHV0KVxuXHRcdCkge1xuXHRcdFx0ZXJyb3IoXG5cdFx0XHRcdCdJbnZhbGlkIGNoYXJhY3RlcjogdGhlIHN0cmluZyB0byBiZSBkZWNvZGVkIGlzIG5vdCBjb3JyZWN0bHkgZW5jb2RlZC4nXG5cdFx0XHQpO1xuXHRcdH1cblx0XHR2YXIgYml0Q291bnRlciA9IDA7XG5cdFx0dmFyIGJpdFN0b3JhZ2U7XG5cdFx0dmFyIGJ1ZmZlcjtcblx0XHR2YXIgb3V0cHV0ID0gJyc7XG5cdFx0dmFyIHBvc2l0aW9uID0gLTE7XG5cdFx0d2hpbGUgKCsrcG9zaXRpb24gPCBsZW5ndGgpIHtcblx0XHRcdGJ1ZmZlciA9IFRBQkxFLmluZGV4T2YoaW5wdXQuY2hhckF0KHBvc2l0aW9uKSk7XG5cdFx0XHRiaXRTdG9yYWdlID0gYml0Q291bnRlciAlIDQgPyBiaXRTdG9yYWdlICogNjQgKyBidWZmZXIgOiBidWZmZXI7XG5cdFx0XHQvLyBVbmxlc3MgdGhpcyBpcyB0aGUgZmlyc3Qgb2YgYSBncm91cCBvZiA0IGNoYXJhY3RlcnPigKZcblx0XHRcdGlmIChiaXRDb3VudGVyKysgJSA0KSB7XG5cdFx0XHRcdC8vIOKApmNvbnZlcnQgdGhlIGZpcnN0IDggYml0cyB0byBhIHNpbmdsZSBBU0NJSSBjaGFyYWN0ZXIuXG5cdFx0XHRcdG91dHB1dCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKFxuXHRcdFx0XHRcdDB4RkYgJiBiaXRTdG9yYWdlID4+ICgtMiAqIGJpdENvdW50ZXIgJiA2KVxuXHRcdFx0XHQpO1xuXHRcdFx0fVxuXHRcdH1cblx0XHRyZXR1cm4gb3V0cHV0O1xuXHR9O1xuXG5cdC8vIGBlbmNvZGVgIGlzIGRlc2lnbmVkIHRvIGJlIGZ1bGx5IGNvbXBhdGlibGUgd2l0aCBgYnRvYWAgYXMgZGVzY3JpYmVkIGluIHRoZVxuXHQvLyBIVE1MIFN0YW5kYXJkOiBodHRwOi8vd2hhdHdnLm9yZy9odG1sL3dlYmFwcGFwaXMuaHRtbCNkb20td2luZG93YmFzZTY0LWJ0b2Fcblx0dmFyIGVuY29kZSA9IGZ1bmN0aW9uKGlucHV0KSB7XG5cdFx0aW5wdXQgPSBTdHJpbmcoaW5wdXQpO1xuXHRcdGlmICgvW15cXDAtXFx4RkZdLy50ZXN0KGlucHV0KSkge1xuXHRcdFx0Ly8gTm90ZTogbm8gbmVlZCB0byBzcGVjaWFsLWNhc2UgYXN0cmFsIHN5bWJvbHMgaGVyZSwgYXMgc3Vycm9nYXRlcyBhcmVcblx0XHRcdC8vIG1hdGNoZWQsIGFuZCB0aGUgaW5wdXQgaXMgc3VwcG9zZWQgdG8gb25seSBjb250YWluIEFTQ0lJIGFueXdheS5cblx0XHRcdGVycm9yKFxuXHRcdFx0XHQnVGhlIHN0cmluZyB0byBiZSBlbmNvZGVkIGNvbnRhaW5zIGNoYXJhY3RlcnMgb3V0c2lkZSBvZiB0aGUgJyArXG5cdFx0XHRcdCdMYXRpbjEgcmFuZ2UuJ1xuXHRcdFx0KTtcblx0XHR9XG5cdFx0dmFyIHBhZGRpbmcgPSBpbnB1dC5sZW5ndGggJSAzO1xuXHRcdHZhciBvdXRwdXQgPSAnJztcblx0XHR2YXIgcG9zaXRpb24gPSAtMTtcblx0XHR2YXIgYTtcblx0XHR2YXIgYjtcblx0XHR2YXIgYztcblx0XHR2YXIgZDtcblx0XHR2YXIgYnVmZmVyO1xuXHRcdC8vIE1ha2Ugc3VyZSBhbnkgcGFkZGluZyBpcyBoYW5kbGVkIG91dHNpZGUgb2YgdGhlIGxvb3AuXG5cdFx0dmFyIGxlbmd0aCA9IGlucHV0Lmxlbmd0aCAtIHBhZGRpbmc7XG5cblx0XHR3aGlsZSAoKytwb3NpdGlvbiA8IGxlbmd0aCkge1xuXHRcdFx0Ly8gUmVhZCB0aHJlZSBieXRlcywgaS5lLiAyNCBiaXRzLlxuXHRcdFx0YSA9IGlucHV0LmNoYXJDb2RlQXQocG9zaXRpb24pIDw8IDE2O1xuXHRcdFx0YiA9IGlucHV0LmNoYXJDb2RlQXQoKytwb3NpdGlvbikgPDwgODtcblx0XHRcdGMgPSBpbnB1dC5jaGFyQ29kZUF0KCsrcG9zaXRpb24pO1xuXHRcdFx0YnVmZmVyID0gYSArIGIgKyBjO1xuXHRcdFx0Ly8gVHVybiB0aGUgMjQgYml0cyBpbnRvIGZvdXIgY2h1bmtzIG9mIDYgYml0cyBlYWNoLCBhbmQgYXBwZW5kIHRoZVxuXHRcdFx0Ly8gbWF0Y2hpbmcgY2hhcmFjdGVyIGZvciBlYWNoIG9mIHRoZW0gdG8gdGhlIG91dHB1dC5cblx0XHRcdG91dHB1dCArPSAoXG5cdFx0XHRcdFRBQkxFLmNoYXJBdChidWZmZXIgPj4gMTggJiAweDNGKSArXG5cdFx0XHRcdFRBQkxFLmNoYXJBdChidWZmZXIgPj4gMTIgJiAweDNGKSArXG5cdFx0XHRcdFRBQkxFLmNoYXJBdChidWZmZXIgPj4gNiAmIDB4M0YpICtcblx0XHRcdFx0VEFCTEUuY2hhckF0KGJ1ZmZlciAmIDB4M0YpXG5cdFx0XHQpO1xuXHRcdH1cblxuXHRcdGlmIChwYWRkaW5nID09IDIpIHtcblx0XHRcdGEgPSBpbnB1dC5jaGFyQ29kZUF0KHBvc2l0aW9uKSA8PCA4O1xuXHRcdFx0YiA9IGlucHV0LmNoYXJDb2RlQXQoKytwb3NpdGlvbik7XG5cdFx0XHRidWZmZXIgPSBhICsgYjtcblx0XHRcdG91dHB1dCArPSAoXG5cdFx0XHRcdFRBQkxFLmNoYXJBdChidWZmZXIgPj4gMTApICtcblx0XHRcdFx0VEFCTEUuY2hhckF0KChidWZmZXIgPj4gNCkgJiAweDNGKSArXG5cdFx0XHRcdFRBQkxFLmNoYXJBdCgoYnVmZmVyIDw8IDIpICYgMHgzRikgK1xuXHRcdFx0XHQnPSdcblx0XHRcdCk7XG5cdFx0fSBlbHNlIGlmIChwYWRkaW5nID09IDEpIHtcblx0XHRcdGJ1ZmZlciA9IGlucHV0LmNoYXJDb2RlQXQocG9zaXRpb24pO1xuXHRcdFx0b3V0cHV0ICs9IChcblx0XHRcdFx0VEFCTEUuY2hhckF0KGJ1ZmZlciA+PiAyKSArXG5cdFx0XHRcdFRBQkxFLmNoYXJBdCgoYnVmZmVyIDw8IDQpICYgMHgzRikgK1xuXHRcdFx0XHQnPT0nXG5cdFx0XHQpO1xuXHRcdH1cblxuXHRcdHJldHVybiBvdXRwdXQ7XG5cdH07XG5cblx0dmFyIGJhc2U2NCA9IHtcblx0XHQnZW5jb2RlJzogZW5jb2RlLFxuXHRcdCdkZWNvZGUnOiBkZWNvZGUsXG5cdFx0J3ZlcnNpb24nOiAnMC4xLjAnXG5cdH07XG5cblx0Ly8gU29tZSBBTUQgYnVpbGQgb3B0aW1pemVycywgbGlrZSByLmpzLCBjaGVjayBmb3Igc3BlY2lmaWMgY29uZGl0aW9uIHBhdHRlcm5zXG5cdC8vIGxpa2UgdGhlIGZvbGxvd2luZzpcblx0aWYgKFxuXHRcdHR5cGVvZiBkZWZpbmUgPT0gJ2Z1bmN0aW9uJyAmJlxuXHRcdHR5cGVvZiBkZWZpbmUuYW1kID09ICdvYmplY3QnICYmXG5cdFx0ZGVmaW5lLmFtZFxuXHQpIHtcblx0XHRkZWZpbmUoZnVuY3Rpb24oKSB7XG5cdFx0XHRyZXR1cm4gYmFzZTY0O1xuXHRcdH0pO1xuXHR9XHRlbHNlIGlmIChmcmVlRXhwb3J0cyAmJiAhZnJlZUV4cG9ydHMubm9kZVR5cGUpIHtcblx0XHRpZiAoZnJlZU1vZHVsZSkgeyAvLyBpbiBOb2RlLmpzIG9yIFJpbmdvSlMgdjAuOC4wK1xuXHRcdFx0ZnJlZU1vZHVsZS5leHBvcnRzID0gYmFzZTY0O1xuXHRcdH0gZWxzZSB7IC8vIGluIE5hcndoYWwgb3IgUmluZ29KUyB2MC43LjAtXG5cdFx0XHRmb3IgKHZhciBrZXkgaW4gYmFzZTY0KSB7XG5cdFx0XHRcdGJhc2U2NC5oYXNPd25Qcm9wZXJ0eShrZXkpICYmIChmcmVlRXhwb3J0c1trZXldID0gYmFzZTY0W2tleV0pO1xuXHRcdFx0fVxuXHRcdH1cblx0fSBlbHNlIHsgLy8gaW4gUmhpbm8gb3IgYSB3ZWIgYnJvd3NlclxuXHRcdHJvb3QuYmFzZTY0ID0gYmFzZTY0O1xuXHR9XG5cbn0odGhpcykpO1xuIiwiLyohIGh0dHBzOi8vbXRocy5iZS9wdW55Y29kZSB2MS40LjEgYnkgQG1hdGhpYXMgKi9cbjsoZnVuY3Rpb24ocm9vdCkge1xuXG5cdC8qKiBEZXRlY3QgZnJlZSB2YXJpYWJsZXMgKi9cblx0dmFyIGZyZWVFeHBvcnRzID0gdHlwZW9mIGV4cG9ydHMgPT0gJ29iamVjdCcgJiYgZXhwb3J0cyAmJlxuXHRcdCFleHBvcnRzLm5vZGVUeXBlICYmIGV4cG9ydHM7XG5cdHZhciBmcmVlTW9kdWxlID0gdHlwZW9mIG1vZHVsZSA9PSAnb2JqZWN0JyAmJiBtb2R1bGUgJiZcblx0XHQhbW9kdWxlLm5vZGVUeXBlICYmIG1vZHVsZTtcblx0dmFyIGZyZWVHbG9iYWwgPSB0eXBlb2YgZ2xvYmFsID09ICdvYmplY3QnICYmIGdsb2JhbDtcblx0aWYgKFxuXHRcdGZyZWVHbG9iYWwuZ2xvYmFsID09PSBmcmVlR2xvYmFsIHx8XG5cdFx0ZnJlZUdsb2JhbC53aW5kb3cgPT09IGZyZWVHbG9iYWwgfHxcblx0XHRmcmVlR2xvYmFsLnNlbGYgPT09IGZyZWVHbG9iYWxcblx0KSB7XG5cdFx0cm9vdCA9IGZyZWVHbG9iYWw7XG5cdH1cblxuXHQvKipcblx0ICogVGhlIGBwdW55Y29kZWAgb2JqZWN0LlxuXHQgKiBAbmFtZSBwdW55Y29kZVxuXHQgKiBAdHlwZSBPYmplY3Rcblx0ICovXG5cdHZhciBwdW55Y29kZSxcblxuXHQvKiogSGlnaGVzdCBwb3NpdGl2ZSBzaWduZWQgMzItYml0IGZsb2F0IHZhbHVlICovXG5cdG1heEludCA9IDIxNDc0ODM2NDcsIC8vIGFrYS4gMHg3RkZGRkZGRiBvciAyXjMxLTFcblxuXHQvKiogQm9vdHN0cmluZyBwYXJhbWV0ZXJzICovXG5cdGJhc2UgPSAzNixcblx0dE1pbiA9IDEsXG5cdHRNYXggPSAyNixcblx0c2tldyA9IDM4LFxuXHRkYW1wID0gNzAwLFxuXHRpbml0aWFsQmlhcyA9IDcyLFxuXHRpbml0aWFsTiA9IDEyOCwgLy8gMHg4MFxuXHRkZWxpbWl0ZXIgPSAnLScsIC8vICdcXHgyRCdcblxuXHQvKiogUmVndWxhciBleHByZXNzaW9ucyAqL1xuXHRyZWdleFB1bnljb2RlID0gL154bi0tLyxcblx0cmVnZXhOb25BU0NJSSA9IC9bXlxceDIwLVxceDdFXS8sIC8vIHVucHJpbnRhYmxlIEFTQ0lJIGNoYXJzICsgbm9uLUFTQ0lJIGNoYXJzXG5cdHJlZ2V4U2VwYXJhdG9ycyA9IC9bXFx4MkVcXHUzMDAyXFx1RkYwRVxcdUZGNjFdL2csIC8vIFJGQyAzNDkwIHNlcGFyYXRvcnNcblxuXHQvKiogRXJyb3IgbWVzc2FnZXMgKi9cblx0ZXJyb3JzID0ge1xuXHRcdCdvdmVyZmxvdyc6ICdPdmVyZmxvdzogaW5wdXQgbmVlZHMgd2lkZXIgaW50ZWdlcnMgdG8gcHJvY2VzcycsXG5cdFx0J25vdC1iYXNpYyc6ICdJbGxlZ2FsIGlucHV0ID49IDB4ODAgKG5vdCBhIGJhc2ljIGNvZGUgcG9pbnQpJyxcblx0XHQnaW52YWxpZC1pbnB1dCc6ICdJbnZhbGlkIGlucHV0J1xuXHR9LFxuXG5cdC8qKiBDb252ZW5pZW5jZSBzaG9ydGN1dHMgKi9cblx0YmFzZU1pbnVzVE1pbiA9IGJhc2UgLSB0TWluLFxuXHRmbG9vciA9IE1hdGguZmxvb3IsXG5cdHN0cmluZ0Zyb21DaGFyQ29kZSA9IFN0cmluZy5mcm9tQ2hhckNvZGUsXG5cblx0LyoqIFRlbXBvcmFyeSB2YXJpYWJsZSAqL1xuXHRrZXk7XG5cblx0LyotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSovXG5cblx0LyoqXG5cdCAqIEEgZ2VuZXJpYyBlcnJvciB1dGlsaXR5IGZ1bmN0aW9uLlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gdHlwZSBUaGUgZXJyb3IgdHlwZS5cblx0ICogQHJldHVybnMge0Vycm9yfSBUaHJvd3MgYSBgUmFuZ2VFcnJvcmAgd2l0aCB0aGUgYXBwbGljYWJsZSBlcnJvciBtZXNzYWdlLlxuXHQgKi9cblx0ZnVuY3Rpb24gZXJyb3IodHlwZSkge1xuXHRcdHRocm93IG5ldyBSYW5nZUVycm9yKGVycm9yc1t0eXBlXSk7XG5cdH1cblxuXHQvKipcblx0ICogQSBnZW5lcmljIGBBcnJheSNtYXBgIHV0aWxpdHkgZnVuY3Rpb24uXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7QXJyYXl9IGFycmF5IFRoZSBhcnJheSB0byBpdGVyYXRlIG92ZXIuXG5cdCAqIEBwYXJhbSB7RnVuY3Rpb259IGNhbGxiYWNrIFRoZSBmdW5jdGlvbiB0aGF0IGdldHMgY2FsbGVkIGZvciBldmVyeSBhcnJheVxuXHQgKiBpdGVtLlxuXHQgKiBAcmV0dXJucyB7QXJyYXl9IEEgbmV3IGFycmF5IG9mIHZhbHVlcyByZXR1cm5lZCBieSB0aGUgY2FsbGJhY2sgZnVuY3Rpb24uXG5cdCAqL1xuXHRmdW5jdGlvbiBtYXAoYXJyYXksIGZuKSB7XG5cdFx0dmFyIGxlbmd0aCA9IGFycmF5Lmxlbmd0aDtcblx0XHR2YXIgcmVzdWx0ID0gW107XG5cdFx0d2hpbGUgKGxlbmd0aC0tKSB7XG5cdFx0XHRyZXN1bHRbbGVuZ3RoXSA9IGZuKGFycmF5W2xlbmd0aF0pO1xuXHRcdH1cblx0XHRyZXR1cm4gcmVzdWx0O1xuXHR9XG5cblx0LyoqXG5cdCAqIEEgc2ltcGxlIGBBcnJheSNtYXBgLWxpa2Ugd3JhcHBlciB0byB3b3JrIHdpdGggZG9tYWluIG5hbWUgc3RyaW5ncyBvciBlbWFpbFxuXHQgKiBhZGRyZXNzZXMuXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBkb21haW4gVGhlIGRvbWFpbiBuYW1lIG9yIGVtYWlsIGFkZHJlc3MuXG5cdCAqIEBwYXJhbSB7RnVuY3Rpb259IGNhbGxiYWNrIFRoZSBmdW5jdGlvbiB0aGF0IGdldHMgY2FsbGVkIGZvciBldmVyeVxuXHQgKiBjaGFyYWN0ZXIuXG5cdCAqIEByZXR1cm5zIHtBcnJheX0gQSBuZXcgc3RyaW5nIG9mIGNoYXJhY3RlcnMgcmV0dXJuZWQgYnkgdGhlIGNhbGxiYWNrXG5cdCAqIGZ1bmN0aW9uLlxuXHQgKi9cblx0ZnVuY3Rpb24gbWFwRG9tYWluKHN0cmluZywgZm4pIHtcblx0XHR2YXIgcGFydHMgPSBzdHJpbmcuc3BsaXQoJ0AnKTtcblx0XHR2YXIgcmVzdWx0ID0gJyc7XG5cdFx0aWYgKHBhcnRzLmxlbmd0aCA+IDEpIHtcblx0XHRcdC8vIEluIGVtYWlsIGFkZHJlc3Nlcywgb25seSB0aGUgZG9tYWluIG5hbWUgc2hvdWxkIGJlIHB1bnljb2RlZC4gTGVhdmVcblx0XHRcdC8vIHRoZSBsb2NhbCBwYXJ0IChpLmUuIGV2ZXJ5dGhpbmcgdXAgdG8gYEBgKSBpbnRhY3QuXG5cdFx0XHRyZXN1bHQgPSBwYXJ0c1swXSArICdAJztcblx0XHRcdHN0cmluZyA9IHBhcnRzWzFdO1xuXHRcdH1cblx0XHQvLyBBdm9pZCBgc3BsaXQocmVnZXgpYCBmb3IgSUU4IGNvbXBhdGliaWxpdHkuIFNlZSAjMTcuXG5cdFx0c3RyaW5nID0gc3RyaW5nLnJlcGxhY2UocmVnZXhTZXBhcmF0b3JzLCAnXFx4MkUnKTtcblx0XHR2YXIgbGFiZWxzID0gc3RyaW5nLnNwbGl0KCcuJyk7XG5cdFx0dmFyIGVuY29kZWQgPSBtYXAobGFiZWxzLCBmbikuam9pbignLicpO1xuXHRcdHJldHVybiByZXN1bHQgKyBlbmNvZGVkO1xuXHR9XG5cblx0LyoqXG5cdCAqIENyZWF0ZXMgYW4gYXJyYXkgY29udGFpbmluZyB0aGUgbnVtZXJpYyBjb2RlIHBvaW50cyBvZiBlYWNoIFVuaWNvZGVcblx0ICogY2hhcmFjdGVyIGluIHRoZSBzdHJpbmcuIFdoaWxlIEphdmFTY3JpcHQgdXNlcyBVQ1MtMiBpbnRlcm5hbGx5LFxuXHQgKiB0aGlzIGZ1bmN0aW9uIHdpbGwgY29udmVydCBhIHBhaXIgb2Ygc3Vycm9nYXRlIGhhbHZlcyAoZWFjaCBvZiB3aGljaFxuXHQgKiBVQ1MtMiBleHBvc2VzIGFzIHNlcGFyYXRlIGNoYXJhY3RlcnMpIGludG8gYSBzaW5nbGUgY29kZSBwb2ludCxcblx0ICogbWF0Y2hpbmcgVVRGLTE2LlxuXHQgKiBAc2VlIGBwdW55Y29kZS51Y3MyLmVuY29kZWBcblx0ICogQHNlZSA8aHR0cHM6Ly9tYXRoaWFzYnluZW5zLmJlL25vdGVzL2phdmFzY3JpcHQtZW5jb2Rpbmc+XG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZS51Y3MyXG5cdCAqIEBuYW1lIGRlY29kZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyaW5nIFRoZSBVbmljb2RlIGlucHV0IHN0cmluZyAoVUNTLTIpLlxuXHQgKiBAcmV0dXJucyB7QXJyYXl9IFRoZSBuZXcgYXJyYXkgb2YgY29kZSBwb2ludHMuXG5cdCAqL1xuXHRmdW5jdGlvbiB1Y3MyZGVjb2RlKHN0cmluZykge1xuXHRcdHZhciBvdXRwdXQgPSBbXSxcblx0XHQgICAgY291bnRlciA9IDAsXG5cdFx0ICAgIGxlbmd0aCA9IHN0cmluZy5sZW5ndGgsXG5cdFx0ICAgIHZhbHVlLFxuXHRcdCAgICBleHRyYTtcblx0XHR3aGlsZSAoY291bnRlciA8IGxlbmd0aCkge1xuXHRcdFx0dmFsdWUgPSBzdHJpbmcuY2hhckNvZGVBdChjb3VudGVyKyspO1xuXHRcdFx0aWYgKHZhbHVlID49IDB4RDgwMCAmJiB2YWx1ZSA8PSAweERCRkYgJiYgY291bnRlciA8IGxlbmd0aCkge1xuXHRcdFx0XHQvLyBoaWdoIHN1cnJvZ2F0ZSwgYW5kIHRoZXJlIGlzIGEgbmV4dCBjaGFyYWN0ZXJcblx0XHRcdFx0ZXh0cmEgPSBzdHJpbmcuY2hhckNvZGVBdChjb3VudGVyKyspO1xuXHRcdFx0XHRpZiAoKGV4dHJhICYgMHhGQzAwKSA9PSAweERDMDApIHsgLy8gbG93IHN1cnJvZ2F0ZVxuXHRcdFx0XHRcdG91dHB1dC5wdXNoKCgodmFsdWUgJiAweDNGRikgPDwgMTApICsgKGV4dHJhICYgMHgzRkYpICsgMHgxMDAwMCk7XG5cdFx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdFx0Ly8gdW5tYXRjaGVkIHN1cnJvZ2F0ZTsgb25seSBhcHBlbmQgdGhpcyBjb2RlIHVuaXQsIGluIGNhc2UgdGhlIG5leHRcblx0XHRcdFx0XHQvLyBjb2RlIHVuaXQgaXMgdGhlIGhpZ2ggc3Vycm9nYXRlIG9mIGEgc3Vycm9nYXRlIHBhaXJcblx0XHRcdFx0XHRvdXRwdXQucHVzaCh2YWx1ZSk7XG5cdFx0XHRcdFx0Y291bnRlci0tO1xuXHRcdFx0XHR9XG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRvdXRwdXQucHVzaCh2YWx1ZSk7XG5cdFx0XHR9XG5cdFx0fVxuXHRcdHJldHVybiBvdXRwdXQ7XG5cdH1cblxuXHQvKipcblx0ICogQ3JlYXRlcyBhIHN0cmluZyBiYXNlZCBvbiBhbiBhcnJheSBvZiBudW1lcmljIGNvZGUgcG9pbnRzLlxuXHQgKiBAc2VlIGBwdW55Y29kZS51Y3MyLmRlY29kZWBcblx0ICogQG1lbWJlck9mIHB1bnljb2RlLnVjczJcblx0ICogQG5hbWUgZW5jb2RlXG5cdCAqIEBwYXJhbSB7QXJyYXl9IGNvZGVQb2ludHMgVGhlIGFycmF5IG9mIG51bWVyaWMgY29kZSBwb2ludHMuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSBuZXcgVW5pY29kZSBzdHJpbmcgKFVDUy0yKS5cblx0ICovXG5cdGZ1bmN0aW9uIHVjczJlbmNvZGUoYXJyYXkpIHtcblx0XHRyZXR1cm4gbWFwKGFycmF5LCBmdW5jdGlvbih2YWx1ZSkge1xuXHRcdFx0dmFyIG91dHB1dCA9ICcnO1xuXHRcdFx0aWYgKHZhbHVlID4gMHhGRkZGKSB7XG5cdFx0XHRcdHZhbHVlIC09IDB4MTAwMDA7XG5cdFx0XHRcdG91dHB1dCArPSBzdHJpbmdGcm9tQ2hhckNvZGUodmFsdWUgPj4+IDEwICYgMHgzRkYgfCAweEQ4MDApO1xuXHRcdFx0XHR2YWx1ZSA9IDB4REMwMCB8IHZhbHVlICYgMHgzRkY7XG5cdFx0XHR9XG5cdFx0XHRvdXRwdXQgKz0gc3RyaW5nRnJvbUNoYXJDb2RlKHZhbHVlKTtcblx0XHRcdHJldHVybiBvdXRwdXQ7XG5cdFx0fSkuam9pbignJyk7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBiYXNpYyBjb2RlIHBvaW50IGludG8gYSBkaWdpdC9pbnRlZ2VyLlxuXHQgKiBAc2VlIGBkaWdpdFRvQmFzaWMoKWBcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IGNvZGVQb2ludCBUaGUgYmFzaWMgbnVtZXJpYyBjb2RlIHBvaW50IHZhbHVlLlxuXHQgKiBAcmV0dXJucyB7TnVtYmVyfSBUaGUgbnVtZXJpYyB2YWx1ZSBvZiBhIGJhc2ljIGNvZGUgcG9pbnQgKGZvciB1c2UgaW5cblx0ICogcmVwcmVzZW50aW5nIGludGVnZXJzKSBpbiB0aGUgcmFuZ2UgYDBgIHRvIGBiYXNlIC0gMWAsIG9yIGBiYXNlYCBpZlxuXHQgKiB0aGUgY29kZSBwb2ludCBkb2VzIG5vdCByZXByZXNlbnQgYSB2YWx1ZS5cblx0ICovXG5cdGZ1bmN0aW9uIGJhc2ljVG9EaWdpdChjb2RlUG9pbnQpIHtcblx0XHRpZiAoY29kZVBvaW50IC0gNDggPCAxMCkge1xuXHRcdFx0cmV0dXJuIGNvZGVQb2ludCAtIDIyO1xuXHRcdH1cblx0XHRpZiAoY29kZVBvaW50IC0gNjUgPCAyNikge1xuXHRcdFx0cmV0dXJuIGNvZGVQb2ludCAtIDY1O1xuXHRcdH1cblx0XHRpZiAoY29kZVBvaW50IC0gOTcgPCAyNikge1xuXHRcdFx0cmV0dXJuIGNvZGVQb2ludCAtIDk3O1xuXHRcdH1cblx0XHRyZXR1cm4gYmFzZTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIGRpZ2l0L2ludGVnZXIgaW50byBhIGJhc2ljIGNvZGUgcG9pbnQuXG5cdCAqIEBzZWUgYGJhc2ljVG9EaWdpdCgpYFxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0gZGlnaXQgVGhlIG51bWVyaWMgdmFsdWUgb2YgYSBiYXNpYyBjb2RlIHBvaW50LlxuXHQgKiBAcmV0dXJucyB7TnVtYmVyfSBUaGUgYmFzaWMgY29kZSBwb2ludCB3aG9zZSB2YWx1ZSAod2hlbiB1c2VkIGZvclxuXHQgKiByZXByZXNlbnRpbmcgaW50ZWdlcnMpIGlzIGBkaWdpdGAsIHdoaWNoIG5lZWRzIHRvIGJlIGluIHRoZSByYW5nZVxuXHQgKiBgMGAgdG8gYGJhc2UgLSAxYC4gSWYgYGZsYWdgIGlzIG5vbi16ZXJvLCB0aGUgdXBwZXJjYXNlIGZvcm0gaXNcblx0ICogdXNlZDsgZWxzZSwgdGhlIGxvd2VyY2FzZSBmb3JtIGlzIHVzZWQuIFRoZSBiZWhhdmlvciBpcyB1bmRlZmluZWRcblx0ICogaWYgYGZsYWdgIGlzIG5vbi16ZXJvIGFuZCBgZGlnaXRgIGhhcyBubyB1cHBlcmNhc2UgZm9ybS5cblx0ICovXG5cdGZ1bmN0aW9uIGRpZ2l0VG9CYXNpYyhkaWdpdCwgZmxhZykge1xuXHRcdC8vICAwLi4yNSBtYXAgdG8gQVNDSUkgYS4ueiBvciBBLi5aXG5cdFx0Ly8gMjYuLjM1IG1hcCB0byBBU0NJSSAwLi45XG5cdFx0cmV0dXJuIGRpZ2l0ICsgMjIgKyA3NSAqIChkaWdpdCA8IDI2KSAtICgoZmxhZyAhPSAwKSA8PCA1KTtcblx0fVxuXG5cdC8qKlxuXHQgKiBCaWFzIGFkYXB0YXRpb24gZnVuY3Rpb24gYXMgcGVyIHNlY3Rpb24gMy40IG9mIFJGQyAzNDkyLlxuXHQgKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjMzQ5MiNzZWN0aW9uLTMuNFxuXHQgKiBAcHJpdmF0ZVxuXHQgKi9cblx0ZnVuY3Rpb24gYWRhcHQoZGVsdGEsIG51bVBvaW50cywgZmlyc3RUaW1lKSB7XG5cdFx0dmFyIGsgPSAwO1xuXHRcdGRlbHRhID0gZmlyc3RUaW1lID8gZmxvb3IoZGVsdGEgLyBkYW1wKSA6IGRlbHRhID4+IDE7XG5cdFx0ZGVsdGEgKz0gZmxvb3IoZGVsdGEgLyBudW1Qb2ludHMpO1xuXHRcdGZvciAoLyogbm8gaW5pdGlhbGl6YXRpb24gKi87IGRlbHRhID4gYmFzZU1pbnVzVE1pbiAqIHRNYXggPj4gMTsgayArPSBiYXNlKSB7XG5cdFx0XHRkZWx0YSA9IGZsb29yKGRlbHRhIC8gYmFzZU1pbnVzVE1pbik7XG5cdFx0fVxuXHRcdHJldHVybiBmbG9vcihrICsgKGJhc2VNaW51c1RNaW4gKyAxKSAqIGRlbHRhIC8gKGRlbHRhICsgc2tldykpO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgUHVueWNvZGUgc3RyaW5nIG9mIEFTQ0lJLW9ubHkgc3ltYm9scyB0byBhIHN0cmluZyBvZiBVbmljb2RlXG5cdCAqIHN5bWJvbHMuXG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgVGhlIFB1bnljb2RlIHN0cmluZyBvZiBBU0NJSS1vbmx5IHN5bWJvbHMuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSByZXN1bHRpbmcgc3RyaW5nIG9mIFVuaWNvZGUgc3ltYm9scy5cblx0ICovXG5cdGZ1bmN0aW9uIGRlY29kZShpbnB1dCkge1xuXHRcdC8vIERvbid0IHVzZSBVQ1MtMlxuXHRcdHZhciBvdXRwdXQgPSBbXSxcblx0XHQgICAgaW5wdXRMZW5ndGggPSBpbnB1dC5sZW5ndGgsXG5cdFx0ICAgIG91dCxcblx0XHQgICAgaSA9IDAsXG5cdFx0ICAgIG4gPSBpbml0aWFsTixcblx0XHQgICAgYmlhcyA9IGluaXRpYWxCaWFzLFxuXHRcdCAgICBiYXNpYyxcblx0XHQgICAgaixcblx0XHQgICAgaW5kZXgsXG5cdFx0ICAgIG9sZGksXG5cdFx0ICAgIHcsXG5cdFx0ICAgIGssXG5cdFx0ICAgIGRpZ2l0LFxuXHRcdCAgICB0LFxuXHRcdCAgICAvKiogQ2FjaGVkIGNhbGN1bGF0aW9uIHJlc3VsdHMgKi9cblx0XHQgICAgYmFzZU1pbnVzVDtcblxuXHRcdC8vIEhhbmRsZSB0aGUgYmFzaWMgY29kZSBwb2ludHM6IGxldCBgYmFzaWNgIGJlIHRoZSBudW1iZXIgb2YgaW5wdXQgY29kZVxuXHRcdC8vIHBvaW50cyBiZWZvcmUgdGhlIGxhc3QgZGVsaW1pdGVyLCBvciBgMGAgaWYgdGhlcmUgaXMgbm9uZSwgdGhlbiBjb3B5XG5cdFx0Ly8gdGhlIGZpcnN0IGJhc2ljIGNvZGUgcG9pbnRzIHRvIHRoZSBvdXRwdXQuXG5cblx0XHRiYXNpYyA9IGlucHV0Lmxhc3RJbmRleE9mKGRlbGltaXRlcik7XG5cdFx0aWYgKGJhc2ljIDwgMCkge1xuXHRcdFx0YmFzaWMgPSAwO1xuXHRcdH1cblxuXHRcdGZvciAoaiA9IDA7IGogPCBiYXNpYzsgKytqKSB7XG5cdFx0XHQvLyBpZiBpdCdzIG5vdCBhIGJhc2ljIGNvZGUgcG9pbnRcblx0XHRcdGlmIChpbnB1dC5jaGFyQ29kZUF0KGopID49IDB4ODApIHtcblx0XHRcdFx0ZXJyb3IoJ25vdC1iYXNpYycpO1xuXHRcdFx0fVxuXHRcdFx0b3V0cHV0LnB1c2goaW5wdXQuY2hhckNvZGVBdChqKSk7XG5cdFx0fVxuXG5cdFx0Ly8gTWFpbiBkZWNvZGluZyBsb29wOiBzdGFydCBqdXN0IGFmdGVyIHRoZSBsYXN0IGRlbGltaXRlciBpZiBhbnkgYmFzaWMgY29kZVxuXHRcdC8vIHBvaW50cyB3ZXJlIGNvcGllZDsgc3RhcnQgYXQgdGhlIGJlZ2lubmluZyBvdGhlcndpc2UuXG5cblx0XHRmb3IgKGluZGV4ID0gYmFzaWMgPiAwID8gYmFzaWMgKyAxIDogMDsgaW5kZXggPCBpbnB1dExlbmd0aDsgLyogbm8gZmluYWwgZXhwcmVzc2lvbiAqLykge1xuXG5cdFx0XHQvLyBgaW5kZXhgIGlzIHRoZSBpbmRleCBvZiB0aGUgbmV4dCBjaGFyYWN0ZXIgdG8gYmUgY29uc3VtZWQuXG5cdFx0XHQvLyBEZWNvZGUgYSBnZW5lcmFsaXplZCB2YXJpYWJsZS1sZW5ndGggaW50ZWdlciBpbnRvIGBkZWx0YWAsXG5cdFx0XHQvLyB3aGljaCBnZXRzIGFkZGVkIHRvIGBpYC4gVGhlIG92ZXJmbG93IGNoZWNraW5nIGlzIGVhc2llclxuXHRcdFx0Ly8gaWYgd2UgaW5jcmVhc2UgYGlgIGFzIHdlIGdvLCB0aGVuIHN1YnRyYWN0IG9mZiBpdHMgc3RhcnRpbmdcblx0XHRcdC8vIHZhbHVlIGF0IHRoZSBlbmQgdG8gb2J0YWluIGBkZWx0YWAuXG5cdFx0XHRmb3IgKG9sZGkgPSBpLCB3ID0gMSwgayA9IGJhc2U7IC8qIG5vIGNvbmRpdGlvbiAqLzsgayArPSBiYXNlKSB7XG5cblx0XHRcdFx0aWYgKGluZGV4ID49IGlucHV0TGVuZ3RoKSB7XG5cdFx0XHRcdFx0ZXJyb3IoJ2ludmFsaWQtaW5wdXQnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGRpZ2l0ID0gYmFzaWNUb0RpZ2l0KGlucHV0LmNoYXJDb2RlQXQoaW5kZXgrKykpO1xuXG5cdFx0XHRcdGlmIChkaWdpdCA+PSBiYXNlIHx8IGRpZ2l0ID4gZmxvb3IoKG1heEludCAtIGkpIC8gdykpIHtcblx0XHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGkgKz0gZGlnaXQgKiB3O1xuXHRcdFx0XHR0ID0gayA8PSBiaWFzID8gdE1pbiA6IChrID49IGJpYXMgKyB0TWF4ID8gdE1heCA6IGsgLSBiaWFzKTtcblxuXHRcdFx0XHRpZiAoZGlnaXQgPCB0KSB7XG5cdFx0XHRcdFx0YnJlYWs7XG5cdFx0XHRcdH1cblxuXHRcdFx0XHRiYXNlTWludXNUID0gYmFzZSAtIHQ7XG5cdFx0XHRcdGlmICh3ID4gZmxvb3IobWF4SW50IC8gYmFzZU1pbnVzVCkpIHtcblx0XHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdHcgKj0gYmFzZU1pbnVzVDtcblxuXHRcdFx0fVxuXG5cdFx0XHRvdXQgPSBvdXRwdXQubGVuZ3RoICsgMTtcblx0XHRcdGJpYXMgPSBhZGFwdChpIC0gb2xkaSwgb3V0LCBvbGRpID09IDApO1xuXG5cdFx0XHQvLyBgaWAgd2FzIHN1cHBvc2VkIHRvIHdyYXAgYXJvdW5kIGZyb20gYG91dGAgdG8gYDBgLFxuXHRcdFx0Ly8gaW5jcmVtZW50aW5nIGBuYCBlYWNoIHRpbWUsIHNvIHdlJ2xsIGZpeCB0aGF0IG5vdzpcblx0XHRcdGlmIChmbG9vcihpIC8gb3V0KSA+IG1heEludCAtIG4pIHtcblx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHR9XG5cblx0XHRcdG4gKz0gZmxvb3IoaSAvIG91dCk7XG5cdFx0XHRpICU9IG91dDtcblxuXHRcdFx0Ly8gSW5zZXJ0IGBuYCBhdCBwb3NpdGlvbiBgaWAgb2YgdGhlIG91dHB1dFxuXHRcdFx0b3V0cHV0LnNwbGljZShpKyssIDAsIG4pO1xuXG5cdFx0fVxuXG5cdFx0cmV0dXJuIHVjczJlbmNvZGUob3V0cHV0KTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIHN0cmluZyBvZiBVbmljb2RlIHN5bWJvbHMgKGUuZy4gYSBkb21haW4gbmFtZSBsYWJlbCkgdG8gYVxuXHQgKiBQdW55Y29kZSBzdHJpbmcgb2YgQVNDSUktb25seSBzeW1ib2xzLlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IFRoZSBzdHJpbmcgb2YgVW5pY29kZSBzeW1ib2xzLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgcmVzdWx0aW5nIFB1bnljb2RlIHN0cmluZyBvZiBBU0NJSS1vbmx5IHN5bWJvbHMuXG5cdCAqL1xuXHRmdW5jdGlvbiBlbmNvZGUoaW5wdXQpIHtcblx0XHR2YXIgbixcblx0XHQgICAgZGVsdGEsXG5cdFx0ICAgIGhhbmRsZWRDUENvdW50LFxuXHRcdCAgICBiYXNpY0xlbmd0aCxcblx0XHQgICAgYmlhcyxcblx0XHQgICAgaixcblx0XHQgICAgbSxcblx0XHQgICAgcSxcblx0XHQgICAgayxcblx0XHQgICAgdCxcblx0XHQgICAgY3VycmVudFZhbHVlLFxuXHRcdCAgICBvdXRwdXQgPSBbXSxcblx0XHQgICAgLyoqIGBpbnB1dExlbmd0aGAgd2lsbCBob2xkIHRoZSBudW1iZXIgb2YgY29kZSBwb2ludHMgaW4gYGlucHV0YC4gKi9cblx0XHQgICAgaW5wdXRMZW5ndGgsXG5cdFx0ICAgIC8qKiBDYWNoZWQgY2FsY3VsYXRpb24gcmVzdWx0cyAqL1xuXHRcdCAgICBoYW5kbGVkQ1BDb3VudFBsdXNPbmUsXG5cdFx0ICAgIGJhc2VNaW51c1QsXG5cdFx0ICAgIHFNaW51c1Q7XG5cblx0XHQvLyBDb252ZXJ0IHRoZSBpbnB1dCBpbiBVQ1MtMiB0byBVbmljb2RlXG5cdFx0aW5wdXQgPSB1Y3MyZGVjb2RlKGlucHV0KTtcblxuXHRcdC8vIENhY2hlIHRoZSBsZW5ndGhcblx0XHRpbnB1dExlbmd0aCA9IGlucHV0Lmxlbmd0aDtcblxuXHRcdC8vIEluaXRpYWxpemUgdGhlIHN0YXRlXG5cdFx0biA9IGluaXRpYWxOO1xuXHRcdGRlbHRhID0gMDtcblx0XHRiaWFzID0gaW5pdGlhbEJpYXM7XG5cblx0XHQvLyBIYW5kbGUgdGhlIGJhc2ljIGNvZGUgcG9pbnRzXG5cdFx0Zm9yIChqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdGN1cnJlbnRWYWx1ZSA9IGlucHV0W2pdO1xuXHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA8IDB4ODApIHtcblx0XHRcdFx0b3V0cHV0LnB1c2goc3RyaW5nRnJvbUNoYXJDb2RlKGN1cnJlbnRWYWx1ZSkpO1xuXHRcdFx0fVxuXHRcdH1cblxuXHRcdGhhbmRsZWRDUENvdW50ID0gYmFzaWNMZW5ndGggPSBvdXRwdXQubGVuZ3RoO1xuXG5cdFx0Ly8gYGhhbmRsZWRDUENvdW50YCBpcyB0aGUgbnVtYmVyIG9mIGNvZGUgcG9pbnRzIHRoYXQgaGF2ZSBiZWVuIGhhbmRsZWQ7XG5cdFx0Ly8gYGJhc2ljTGVuZ3RoYCBpcyB0aGUgbnVtYmVyIG9mIGJhc2ljIGNvZGUgcG9pbnRzLlxuXG5cdFx0Ly8gRmluaXNoIHRoZSBiYXNpYyBzdHJpbmcgLSBpZiBpdCBpcyBub3QgZW1wdHkgLSB3aXRoIGEgZGVsaW1pdGVyXG5cdFx0aWYgKGJhc2ljTGVuZ3RoKSB7XG5cdFx0XHRvdXRwdXQucHVzaChkZWxpbWl0ZXIpO1xuXHRcdH1cblxuXHRcdC8vIE1haW4gZW5jb2RpbmcgbG9vcDpcblx0XHR3aGlsZSAoaGFuZGxlZENQQ291bnQgPCBpbnB1dExlbmd0aCkge1xuXG5cdFx0XHQvLyBBbGwgbm9uLWJhc2ljIGNvZGUgcG9pbnRzIDwgbiBoYXZlIGJlZW4gaGFuZGxlZCBhbHJlYWR5LiBGaW5kIHRoZSBuZXh0XG5cdFx0XHQvLyBsYXJnZXIgb25lOlxuXHRcdFx0Zm9yIChtID0gbWF4SW50LCBqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdFx0Y3VycmVudFZhbHVlID0gaW5wdXRbal07XG5cdFx0XHRcdGlmIChjdXJyZW50VmFsdWUgPj0gbiAmJiBjdXJyZW50VmFsdWUgPCBtKSB7XG5cdFx0XHRcdFx0bSA9IGN1cnJlbnRWYWx1ZTtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXG5cdFx0XHQvLyBJbmNyZWFzZSBgZGVsdGFgIGVub3VnaCB0byBhZHZhbmNlIHRoZSBkZWNvZGVyJ3MgPG4saT4gc3RhdGUgdG8gPG0sMD4sXG5cdFx0XHQvLyBidXQgZ3VhcmQgYWdhaW5zdCBvdmVyZmxvd1xuXHRcdFx0aGFuZGxlZENQQ291bnRQbHVzT25lID0gaGFuZGxlZENQQ291bnQgKyAxO1xuXHRcdFx0aWYgKG0gLSBuID4gZmxvb3IoKG1heEludCAtIGRlbHRhKSAvIGhhbmRsZWRDUENvdW50UGx1c09uZSkpIHtcblx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHR9XG5cblx0XHRcdGRlbHRhICs9IChtIC0gbikgKiBoYW5kbGVkQ1BDb3VudFBsdXNPbmU7XG5cdFx0XHRuID0gbTtcblxuXHRcdFx0Zm9yIChqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdFx0Y3VycmVudFZhbHVlID0gaW5wdXRbal07XG5cblx0XHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA8IG4gJiYgKytkZWx0YSA+IG1heEludCkge1xuXHRcdFx0XHRcdGVycm9yKCdvdmVyZmxvdycpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA9PSBuKSB7XG5cdFx0XHRcdFx0Ly8gUmVwcmVzZW50IGRlbHRhIGFzIGEgZ2VuZXJhbGl6ZWQgdmFyaWFibGUtbGVuZ3RoIGludGVnZXJcblx0XHRcdFx0XHRmb3IgKHEgPSBkZWx0YSwgayA9IGJhc2U7IC8qIG5vIGNvbmRpdGlvbiAqLzsgayArPSBiYXNlKSB7XG5cdFx0XHRcdFx0XHR0ID0gayA8PSBiaWFzID8gdE1pbiA6IChrID49IGJpYXMgKyB0TWF4ID8gdE1heCA6IGsgLSBiaWFzKTtcblx0XHRcdFx0XHRcdGlmIChxIDwgdCkge1xuXHRcdFx0XHRcdFx0XHRicmVhaztcblx0XHRcdFx0XHRcdH1cblx0XHRcdFx0XHRcdHFNaW51c1QgPSBxIC0gdDtcblx0XHRcdFx0XHRcdGJhc2VNaW51c1QgPSBiYXNlIC0gdDtcblx0XHRcdFx0XHRcdG91dHB1dC5wdXNoKFxuXHRcdFx0XHRcdFx0XHRzdHJpbmdGcm9tQ2hhckNvZGUoZGlnaXRUb0Jhc2ljKHQgKyBxTWludXNUICUgYmFzZU1pbnVzVCwgMCkpXG5cdFx0XHRcdFx0XHQpO1xuXHRcdFx0XHRcdFx0cSA9IGZsb29yKHFNaW51c1QgLyBiYXNlTWludXNUKTtcblx0XHRcdFx0XHR9XG5cblx0XHRcdFx0XHRvdXRwdXQucHVzaChzdHJpbmdGcm9tQ2hhckNvZGUoZGlnaXRUb0Jhc2ljKHEsIDApKSk7XG5cdFx0XHRcdFx0YmlhcyA9IGFkYXB0KGRlbHRhLCBoYW5kbGVkQ1BDb3VudFBsdXNPbmUsIGhhbmRsZWRDUENvdW50ID09IGJhc2ljTGVuZ3RoKTtcblx0XHRcdFx0XHRkZWx0YSA9IDA7XG5cdFx0XHRcdFx0KytoYW5kbGVkQ1BDb3VudDtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXG5cdFx0XHQrK2RlbHRhO1xuXHRcdFx0KytuO1xuXG5cdFx0fVxuXHRcdHJldHVybiBvdXRwdXQuam9pbignJyk7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBQdW55Y29kZSBzdHJpbmcgcmVwcmVzZW50aW5nIGEgZG9tYWluIG5hbWUgb3IgYW4gZW1haWwgYWRkcmVzc1xuXHQgKiB0byBVbmljb2RlLiBPbmx5IHRoZSBQdW55Y29kZWQgcGFydHMgb2YgdGhlIGlucHV0IHdpbGwgYmUgY29udmVydGVkLCBpLmUuXG5cdCAqIGl0IGRvZXNuJ3QgbWF0dGVyIGlmIHlvdSBjYWxsIGl0IG9uIGEgc3RyaW5nIHRoYXQgaGFzIGFscmVhZHkgYmVlblxuXHQgKiBjb252ZXJ0ZWQgdG8gVW5pY29kZS5cblx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBUaGUgUHVueWNvZGVkIGRvbWFpbiBuYW1lIG9yIGVtYWlsIGFkZHJlc3MgdG9cblx0ICogY29udmVydCB0byBVbmljb2RlLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgVW5pY29kZSByZXByZXNlbnRhdGlvbiBvZiB0aGUgZ2l2ZW4gUHVueWNvZGVcblx0ICogc3RyaW5nLlxuXHQgKi9cblx0ZnVuY3Rpb24gdG9Vbmljb2RlKGlucHV0KSB7XG5cdFx0cmV0dXJuIG1hcERvbWFpbihpbnB1dCwgZnVuY3Rpb24oc3RyaW5nKSB7XG5cdFx0XHRyZXR1cm4gcmVnZXhQdW55Y29kZS50ZXN0KHN0cmluZylcblx0XHRcdFx0PyBkZWNvZGUoc3RyaW5nLnNsaWNlKDQpLnRvTG93ZXJDYXNlKCkpXG5cdFx0XHRcdDogc3RyaW5nO1xuXHRcdH0pO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgVW5pY29kZSBzdHJpbmcgcmVwcmVzZW50aW5nIGEgZG9tYWluIG5hbWUgb3IgYW4gZW1haWwgYWRkcmVzcyB0b1xuXHQgKiBQdW55Y29kZS4gT25seSB0aGUgbm9uLUFTQ0lJIHBhcnRzIG9mIHRoZSBkb21haW4gbmFtZSB3aWxsIGJlIGNvbnZlcnRlZCxcblx0ICogaS5lLiBpdCBkb2Vzbid0IG1hdHRlciBpZiB5b3UgY2FsbCBpdCB3aXRoIGEgZG9tYWluIHRoYXQncyBhbHJlYWR5IGluXG5cdCAqIEFTQ0lJLlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IFRoZSBkb21haW4gbmFtZSBvciBlbWFpbCBhZGRyZXNzIHRvIGNvbnZlcnQsIGFzIGFcblx0ICogVW5pY29kZSBzdHJpbmcuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSBQdW55Y29kZSByZXByZXNlbnRhdGlvbiBvZiB0aGUgZ2l2ZW4gZG9tYWluIG5hbWUgb3Jcblx0ICogZW1haWwgYWRkcmVzcy5cblx0ICovXG5cdGZ1bmN0aW9uIHRvQVNDSUkoaW5wdXQpIHtcblx0XHRyZXR1cm4gbWFwRG9tYWluKGlucHV0LCBmdW5jdGlvbihzdHJpbmcpIHtcblx0XHRcdHJldHVybiByZWdleE5vbkFTQ0lJLnRlc3Qoc3RyaW5nKVxuXHRcdFx0XHQ/ICd4bi0tJyArIGVuY29kZShzdHJpbmcpXG5cdFx0XHRcdDogc3RyaW5nO1xuXHRcdH0pO1xuXHR9XG5cblx0LyotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSovXG5cblx0LyoqIERlZmluZSB0aGUgcHVibGljIEFQSSAqL1xuXHRwdW55Y29kZSA9IHtcblx0XHQvKipcblx0XHQgKiBBIHN0cmluZyByZXByZXNlbnRpbmcgdGhlIGN1cnJlbnQgUHVueWNvZGUuanMgdmVyc2lvbiBudW1iZXIuXG5cdFx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdFx0ICogQHR5cGUgU3RyaW5nXG5cdFx0ICovXG5cdFx0J3ZlcnNpb24nOiAnMS40LjEnLFxuXHRcdC8qKlxuXHRcdCAqIEFuIG9iamVjdCBvZiBtZXRob2RzIHRvIGNvbnZlcnQgZnJvbSBKYXZhU2NyaXB0J3MgaW50ZXJuYWwgY2hhcmFjdGVyXG5cdFx0ICogcmVwcmVzZW50YXRpb24gKFVDUy0yKSB0byBVbmljb2RlIGNvZGUgcG9pbnRzLCBhbmQgYmFjay5cblx0XHQgKiBAc2VlIDxodHRwczovL21hdGhpYXNieW5lbnMuYmUvbm90ZXMvamF2YXNjcmlwdC1lbmNvZGluZz5cblx0XHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0XHQgKiBAdHlwZSBPYmplY3Rcblx0XHQgKi9cblx0XHQndWNzMic6IHtcblx0XHRcdCdkZWNvZGUnOiB1Y3MyZGVjb2RlLFxuXHRcdFx0J2VuY29kZSc6IHVjczJlbmNvZGVcblx0XHR9LFxuXHRcdCdkZWNvZGUnOiBkZWNvZGUsXG5cdFx0J2VuY29kZSc6IGVuY29kZSxcblx0XHQndG9BU0NJSSc6IHRvQVNDSUksXG5cdFx0J3RvVW5pY29kZSc6IHRvVW5pY29kZVxuXHR9O1xuXG5cdC8qKiBFeHBvc2UgYHB1bnljb2RlYCAqL1xuXHQvLyBTb21lIEFNRCBidWlsZCBvcHRpbWl6ZXJzLCBsaWtlIHIuanMsIGNoZWNrIGZvciBzcGVjaWZpYyBjb25kaXRpb24gcGF0dGVybnNcblx0Ly8gbGlrZSB0aGUgZm9sbG93aW5nOlxuXHRpZiAoXG5cdFx0dHlwZW9mIGRlZmluZSA9PSAnZnVuY3Rpb24nICYmXG5cdFx0dHlwZW9mIGRlZmluZS5hbWQgPT0gJ29iamVjdCcgJiZcblx0XHRkZWZpbmUuYW1kXG5cdCkge1xuXHRcdGRlZmluZSgncHVueWNvZGUnLCBmdW5jdGlvbigpIHtcblx0XHRcdHJldHVybiBwdW55Y29kZTtcblx0XHR9KTtcblx0fSBlbHNlIGlmIChmcmVlRXhwb3J0cyAmJiBmcmVlTW9kdWxlKSB7XG5cdFx0aWYgKG1vZHVsZS5leHBvcnRzID09IGZyZWVFeHBvcnRzKSB7XG5cdFx0XHQvLyBpbiBOb2RlLmpzLCBpby5qcywgb3IgUmluZ29KUyB2MC44LjArXG5cdFx0XHRmcmVlTW9kdWxlLmV4cG9ydHMgPSBwdW55Y29kZTtcblx0XHR9IGVsc2Uge1xuXHRcdFx0Ly8gaW4gTmFyd2hhbCBvciBSaW5nb0pTIHYwLjcuMC1cblx0XHRcdGZvciAoa2V5IGluIHB1bnljb2RlKSB7XG5cdFx0XHRcdHB1bnljb2RlLmhhc093blByb3BlcnR5KGtleSkgJiYgKGZyZWVFeHBvcnRzW2tleV0gPSBwdW55Y29kZVtrZXldKTtcblx0XHRcdH1cblx0XHR9XG5cdH0gZWxzZSB7XG5cdFx0Ly8gaW4gUmhpbm8gb3IgYSB3ZWIgYnJvd3NlclxuXHRcdHJvb3QucHVueWNvZGUgPSBwdW55Y29kZTtcblx0fVxuXG59KHRoaXMpKTtcbiIsIi8vIENvcHlyaWdodCBKb3llbnQsIEluYy4gYW5kIG90aGVyIE5vZGUgY29udHJpYnV0b3JzLlxuLy9cbi8vIFBlcm1pc3Npb24gaXMgaGVyZWJ5IGdyYW50ZWQsIGZyZWUgb2YgY2hhcmdlLCB0byBhbnkgcGVyc29uIG9idGFpbmluZyBhXG4vLyBjb3B5IG9mIHRoaXMgc29mdHdhcmUgYW5kIGFzc29jaWF0ZWQgZG9jdW1lbnRhdGlvbiBmaWxlcyAodGhlXG4vLyBcIlNvZnR3YXJlXCIpLCB0byBkZWFsIGluIHRoZSBTb2Z0d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmdcbi8vIHdpdGhvdXQgbGltaXRhdGlvbiB0aGUgcmlnaHRzIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBtZXJnZSwgcHVibGlzaCxcbi8vIGRpc3RyaWJ1dGUsIHN1YmxpY2Vuc2UsIGFuZC9vciBzZWxsIGNvcGllcyBvZiB0aGUgU29mdHdhcmUsIGFuZCB0byBwZXJtaXRcbi8vIHBlcnNvbnMgdG8gd2hvbSB0aGUgU29mdHdhcmUgaXMgZnVybmlzaGVkIHRvIGRvIHNvLCBzdWJqZWN0IHRvIHRoZVxuLy8gZm9sbG93aW5nIGNvbmRpdGlvbnM6XG4vL1xuLy8gVGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2Ugc2hhbGwgYmUgaW5jbHVkZWRcbi8vIGluIGFsbCBjb3BpZXMgb3Igc3Vic3RhbnRpYWwgcG9ydGlvbnMgb2YgdGhlIFNvZnR3YXJlLlxuLy9cbi8vIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIsIFdJVEhPVVQgV0FSUkFOVFkgT0YgQU5ZIEtJTkQsIEVYUFJFU1Ncbi8vIE9SIElNUExJRUQsIElOQ0xVRElORyBCVVQgTk9UIExJTUlURUQgVE8gVEhFIFdBUlJBTlRJRVMgT0Zcbi8vIE1FUkNIQU5UQUJJTElUWSwgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UgQU5EIE5PTklORlJJTkdFTUVOVC4gSU5cbi8vIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1JTIE9SIENPUFlSSUdIVCBIT0xERVJTIEJFIExJQUJMRSBGT1IgQU5ZIENMQUlNLFxuLy8gREFNQUdFUyBPUiBPVEhFUiBMSUFCSUxJVFksIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBUT1JUIE9SXG4vLyBPVEhFUldJU0UsIEFSSVNJTkcgRlJPTSwgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgU09GVFdBUkUgT1IgVEhFXG4vLyBVU0UgT1IgT1RIRVIgREVBTElOR1MgSU4gVEhFIFNPRlRXQVJFLlxuXG4ndXNlIHN0cmljdCc7XG5cbi8vIElmIG9iai5oYXNPd25Qcm9wZXJ0eSBoYXMgYmVlbiBvdmVycmlkZGVuLCB0aGVuIGNhbGxpbmdcbi8vIG9iai5oYXNPd25Qcm9wZXJ0eShwcm9wKSB3aWxsIGJyZWFrLlxuLy8gU2VlOiBodHRwczovL2dpdGh1Yi5jb20vam95ZW50L25vZGUvaXNzdWVzLzE3MDdcbmZ1bmN0aW9uIGhhc093blByb3BlcnR5KG9iaiwgcHJvcCkge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCk7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24ocXMsIHNlcCwgZXEsIG9wdGlvbnMpIHtcbiAgc2VwID0gc2VwIHx8ICcmJztcbiAgZXEgPSBlcSB8fCAnPSc7XG4gIHZhciBvYmogPSB7fTtcblxuICBpZiAodHlwZW9mIHFzICE9PSAnc3RyaW5nJyB8fCBxcy5sZW5ndGggPT09IDApIHtcbiAgICByZXR1cm4gb2JqO1xuICB9XG5cbiAgdmFyIHJlZ2V4cCA9IC9cXCsvZztcbiAgcXMgPSBxcy5zcGxpdChzZXApO1xuXG4gIHZhciBtYXhLZXlzID0gMTAwMDtcbiAgaWYgKG9wdGlvbnMgJiYgdHlwZW9mIG9wdGlvbnMubWF4S2V5cyA9PT0gJ251bWJlcicpIHtcbiAgICBtYXhLZXlzID0gb3B0aW9ucy5tYXhLZXlzO1xuICB9XG5cbiAgdmFyIGxlbiA9IHFzLmxlbmd0aDtcbiAgLy8gbWF4S2V5cyA8PSAwIG1lYW5zIHRoYXQgd2Ugc2hvdWxkIG5vdCBsaW1pdCBrZXlzIGNvdW50XG4gIGlmIChtYXhLZXlzID4gMCAmJiBsZW4gPiBtYXhLZXlzKSB7XG4gICAgbGVuID0gbWF4S2V5cztcbiAgfVxuXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuOyArK2kpIHtcbiAgICB2YXIgeCA9IHFzW2ldLnJlcGxhY2UocmVnZXhwLCAnJTIwJyksXG4gICAgICAgIGlkeCA9IHguaW5kZXhPZihlcSksXG4gICAgICAgIGtzdHIsIHZzdHIsIGssIHY7XG5cbiAgICBpZiAoaWR4ID49IDApIHtcbiAgICAgIGtzdHIgPSB4LnN1YnN0cigwLCBpZHgpO1xuICAgICAgdnN0ciA9IHguc3Vic3RyKGlkeCArIDEpO1xuICAgIH0gZWxzZSB7XG4gICAgICBrc3RyID0geDtcbiAgICAgIHZzdHIgPSAnJztcbiAgICB9XG5cbiAgICBrID0gZGVjb2RlVVJJQ29tcG9uZW50KGtzdHIpO1xuICAgIHYgPSBkZWNvZGVVUklDb21wb25lbnQodnN0cik7XG5cbiAgICBpZiAoIWhhc093blByb3BlcnR5KG9iaiwgaykpIHtcbiAgICAgIG9ialtrXSA9IHY7XG4gICAgfSBlbHNlIGlmIChpc0FycmF5KG9ialtrXSkpIHtcbiAgICAgIG9ialtrXS5wdXNoKHYpO1xuICAgIH0gZWxzZSB7XG4gICAgICBvYmpba10gPSBbb2JqW2tdLCB2XTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gb2JqO1xufTtcblxudmFyIGlzQXJyYXkgPSBBcnJheS5pc0FycmF5IHx8IGZ1bmN0aW9uICh4cykge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHhzKSA9PT0gJ1tvYmplY3QgQXJyYXldJztcbn07XG4iLCIvLyBDb3B5cmlnaHQgSm95ZW50LCBJbmMuIGFuZCBvdGhlciBOb2RlIGNvbnRyaWJ1dG9ycy5cbi8vXG4vLyBQZXJtaXNzaW9uIGlzIGhlcmVieSBncmFudGVkLCBmcmVlIG9mIGNoYXJnZSwgdG8gYW55IHBlcnNvbiBvYnRhaW5pbmcgYVxuLy8gY29weSBvZiB0aGlzIHNvZnR3YXJlIGFuZCBhc3NvY2lhdGVkIGRvY3VtZW50YXRpb24gZmlsZXMgKHRoZVxuLy8gXCJTb2Z0d2FyZVwiKSwgdG8gZGVhbCBpbiB0aGUgU29mdHdhcmUgd2l0aG91dCByZXN0cmljdGlvbiwgaW5jbHVkaW5nXG4vLyB3aXRob3V0IGxpbWl0YXRpb24gdGhlIHJpZ2h0cyB0byB1c2UsIGNvcHksIG1vZGlmeSwgbWVyZ2UsIHB1Ymxpc2gsXG4vLyBkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBhbmQvb3Igc2VsbCBjb3BpZXMgb2YgdGhlIFNvZnR3YXJlLCBhbmQgdG8gcGVybWl0XG4vLyBwZXJzb25zIHRvIHdob20gdGhlIFNvZnR3YXJlIGlzIGZ1cm5pc2hlZCB0byBkbyBzbywgc3ViamVjdCB0byB0aGVcbi8vIGZvbGxvd2luZyBjb25kaXRpb25zOlxuLy9cbi8vIFRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIHNoYWxsIGJlIGluY2x1ZGVkXG4vLyBpbiBhbGwgY29waWVzIG9yIHN1YnN0YW50aWFsIHBvcnRpb25zIG9mIHRoZSBTb2Z0d2FyZS5cbi8vXG4vLyBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiLCBXSVRIT1VUIFdBUlJBTlRZIE9GIEFOWSBLSU5ELCBFWFBSRVNTXG4vLyBPUiBJTVBMSUVELCBJTkNMVURJTkcgQlVUIE5PVCBMSU1JVEVEIFRPIFRIRSBXQVJSQU5USUVTIE9GXG4vLyBNRVJDSEFOVEFCSUxJVFksIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFIEFORCBOT05JTkZSSU5HRU1FTlQuIElOXG4vLyBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SUyBPUiBDT1BZUklHSFQgSE9MREVSUyBCRSBMSUFCTEUgRk9SIEFOWSBDTEFJTSxcbi8vIERBTUFHRVMgT1IgT1RIRVIgTElBQklMSVRZLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgVE9SVCBPUlxuLy8gT1RIRVJXSVNFLCBBUklTSU5HIEZST00sIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFNPRlRXQVJFIE9SIFRIRVxuLy8gVVNFIE9SIE9USEVSIERFQUxJTkdTIElOIFRIRSBTT0ZUV0FSRS5cblxuJ3VzZSBzdHJpY3QnO1xuXG52YXIgc3RyaW5naWZ5UHJpbWl0aXZlID0gZnVuY3Rpb24odikge1xuICBzd2l0Y2ggKHR5cGVvZiB2KSB7XG4gICAgY2FzZSAnc3RyaW5nJzpcbiAgICAgIHJldHVybiB2O1xuXG4gICAgY2FzZSAnYm9vbGVhbic6XG4gICAgICByZXR1cm4gdiA/ICd0cnVlJyA6ICdmYWxzZSc7XG5cbiAgICBjYXNlICdudW1iZXInOlxuICAgICAgcmV0dXJuIGlzRmluaXRlKHYpID8gdiA6ICcnO1xuXG4gICAgZGVmYXVsdDpcbiAgICAgIHJldHVybiAnJztcbiAgfVxufTtcblxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbihvYmosIHNlcCwgZXEsIG5hbWUpIHtcbiAgc2VwID0gc2VwIHx8ICcmJztcbiAgZXEgPSBlcSB8fCAnPSc7XG4gIGlmIChvYmogPT09IG51bGwpIHtcbiAgICBvYmogPSB1bmRlZmluZWQ7XG4gIH1cblxuICBpZiAodHlwZW9mIG9iaiA9PT0gJ29iamVjdCcpIHtcbiAgICByZXR1cm4gbWFwKG9iamVjdEtleXMob2JqKSwgZnVuY3Rpb24oaykge1xuICAgICAgdmFyIGtzID0gZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShrKSkgKyBlcTtcbiAgICAgIGlmIChpc0FycmF5KG9ialtrXSkpIHtcbiAgICAgICAgcmV0dXJuIG1hcChvYmpba10sIGZ1bmN0aW9uKHYpIHtcbiAgICAgICAgICByZXR1cm4ga3MgKyBlbmNvZGVVUklDb21wb25lbnQoc3RyaW5naWZ5UHJpbWl0aXZlKHYpKTtcbiAgICAgICAgfSkuam9pbihzZXApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIGtzICsgZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShvYmpba10pKTtcbiAgICAgIH1cbiAgICB9KS5qb2luKHNlcCk7XG5cbiAgfVxuXG4gIGlmICghbmFtZSkgcmV0dXJuICcnO1xuICByZXR1cm4gZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShuYW1lKSkgKyBlcSArXG4gICAgICAgICBlbmNvZGVVUklDb21wb25lbnQoc3RyaW5naWZ5UHJpbWl0aXZlKG9iaikpO1xufTtcblxudmFyIGlzQXJyYXkgPSBBcnJheS5pc0FycmF5IHx8IGZ1bmN0aW9uICh4cykge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHhzKSA9PT0gJ1tvYmplY3QgQXJyYXldJztcbn07XG5cbmZ1bmN0aW9uIG1hcCAoeHMsIGYpIHtcbiAgaWYgKHhzLm1hcCkgcmV0dXJuIHhzLm1hcChmKTtcbiAgdmFyIHJlcyA9IFtdO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IHhzLmxlbmd0aDsgaSsrKSB7XG4gICAgcmVzLnB1c2goZih4c1tpXSwgaSkpO1xuICB9XG4gIHJldHVybiByZXM7XG59XG5cbnZhciBvYmplY3RLZXlzID0gT2JqZWN0LmtleXMgfHwgZnVuY3Rpb24gKG9iaikge1xuICB2YXIgcmVzID0gW107XG4gIGZvciAodmFyIGtleSBpbiBvYmopIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwga2V5KSkgcmVzLnB1c2goa2V5KTtcbiAgfVxuICByZXR1cm4gcmVzO1xufTtcbiIsIid1c2Ugc3RyaWN0JztcblxuZXhwb3J0cy5kZWNvZGUgPSBleHBvcnRzLnBhcnNlID0gcmVxdWlyZSgnLi9kZWNvZGUnKTtcbmV4cG9ydHMuZW5jb2RlID0gZXhwb3J0cy5zdHJpbmdpZnkgPSByZXF1aXJlKCcuL2VuY29kZScpO1xuIiwiZnVuY3Rpb24gUmF2ZW5Db25maWdFcnJvcihtZXNzYWdlKSB7XG4gIHRoaXMubmFtZSA9ICdSYXZlbkNvbmZpZ0Vycm9yJztcbiAgdGhpcy5tZXNzYWdlID0gbWVzc2FnZTtcbn1cblJhdmVuQ29uZmlnRXJyb3IucHJvdG90eXBlID0gbmV3IEVycm9yKCk7XG5SYXZlbkNvbmZpZ0Vycm9yLnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9IFJhdmVuQ29uZmlnRXJyb3I7XG5cbm1vZHVsZS5leHBvcnRzID0gUmF2ZW5Db25maWdFcnJvcjtcbiIsInZhciB3cmFwTWV0aG9kID0gZnVuY3Rpb24oY29uc29sZSwgbGV2ZWwsIGNhbGxiYWNrKSB7XG4gIHZhciBvcmlnaW5hbENvbnNvbGVMZXZlbCA9IGNvbnNvbGVbbGV2ZWxdO1xuICB2YXIgb3JpZ2luYWxDb25zb2xlID0gY29uc29sZTtcblxuICBpZiAoIShsZXZlbCBpbiBjb25zb2xlKSkge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIHZhciBzZW50cnlMZXZlbCA9IGxldmVsID09PSAnd2FybicgPyAnd2FybmluZycgOiBsZXZlbDtcblxuICBjb25zb2xlW2xldmVsXSA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBhcmdzID0gW10uc2xpY2UuY2FsbChhcmd1bWVudHMpO1xuXG4gICAgdmFyIG1zZyA9ICcnICsgYXJncy5qb2luKCcgJyk7XG4gICAgdmFyIGRhdGEgPSB7bGV2ZWw6IHNlbnRyeUxldmVsLCBsb2dnZXI6ICdjb25zb2xlJywgZXh0cmE6IHthcmd1bWVudHM6IGFyZ3N9fTtcblxuICAgIGlmIChsZXZlbCA9PT0gJ2Fzc2VydCcpIHtcbiAgICAgIGlmIChhcmdzWzBdID09PSBmYWxzZSkge1xuICAgICAgICAvLyBEZWZhdWx0IGJyb3dzZXJzIG1lc3NhZ2VcbiAgICAgICAgbXNnID0gJ0Fzc2VydGlvbiBmYWlsZWQ6ICcgKyAoYXJncy5zbGljZSgxKS5qb2luKCcgJykgfHwgJ2NvbnNvbGUuYXNzZXJ0Jyk7XG4gICAgICAgIGRhdGEuZXh0cmEuYXJndW1lbnRzID0gYXJncy5zbGljZSgxKTtcbiAgICAgICAgY2FsbGJhY2sgJiYgY2FsbGJhY2sobXNnLCBkYXRhKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgY2FsbGJhY2sgJiYgY2FsbGJhY2sobXNnLCBkYXRhKTtcbiAgICB9XG5cbiAgICAvLyB0aGlzIGZhaWxzIGZvciBzb21lIGJyb3dzZXJzLiA6KFxuICAgIGlmIChvcmlnaW5hbENvbnNvbGVMZXZlbCkge1xuICAgICAgLy8gSUU5IGRvZXNuJ3QgYWxsb3cgY2FsbGluZyBhcHBseSBvbiBjb25zb2xlIGZ1bmN0aW9ucyBkaXJlY3RseVxuICAgICAgLy8gU2VlOiBodHRwczovL3N0YWNrb3ZlcmZsb3cuY29tL3F1ZXN0aW9ucy81NDcyOTM4L2RvZXMtaWU5LXN1cHBvcnQtY29uc29sZS1sb2ctYW5kLWlzLWl0LWEtcmVhbC1mdW5jdGlvbiNhbnN3ZXItNTQ3MzE5M1xuICAgICAgRnVuY3Rpb24ucHJvdG90eXBlLmFwcGx5LmNhbGwob3JpZ2luYWxDb25zb2xlTGV2ZWwsIG9yaWdpbmFsQ29uc29sZSwgYXJncyk7XG4gICAgfVxuICB9O1xufTtcblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gIHdyYXBNZXRob2Q6IHdyYXBNZXRob2Rcbn07XG4iLCIvKmdsb2JhbCBYRG9tYWluUmVxdWVzdDpmYWxzZSAqL1xuXG52YXIgVHJhY2VLaXQgPSByZXF1aXJlKCcuLi92ZW5kb3IvVHJhY2VLaXQvdHJhY2VraXQnKTtcbnZhciBzdHJpbmdpZnkgPSByZXF1aXJlKCcuLi92ZW5kb3IvanNvbi1zdHJpbmdpZnktc2FmZS9zdHJpbmdpZnknKTtcbnZhciBSYXZlbkNvbmZpZ0Vycm9yID0gcmVxdWlyZSgnLi9jb25maWdFcnJvcicpO1xuXG52YXIgdXRpbHMgPSByZXF1aXJlKCcuL3V0aWxzJyk7XG52YXIgaXNFcnJvciA9IHV0aWxzLmlzRXJyb3I7XG52YXIgaXNPYmplY3QgPSB1dGlscy5pc09iamVjdDtcbnZhciBpc0Vycm9yRXZlbnQgPSB1dGlscy5pc0Vycm9yRXZlbnQ7XG52YXIgaXNVbmRlZmluZWQgPSB1dGlscy5pc1VuZGVmaW5lZDtcbnZhciBpc0Z1bmN0aW9uID0gdXRpbHMuaXNGdW5jdGlvbjtcbnZhciBpc1N0cmluZyA9IHV0aWxzLmlzU3RyaW5nO1xudmFyIGlzQXJyYXkgPSB1dGlscy5pc0FycmF5O1xudmFyIGlzRW1wdHlPYmplY3QgPSB1dGlscy5pc0VtcHR5T2JqZWN0O1xudmFyIGVhY2ggPSB1dGlscy5lYWNoO1xudmFyIG9iamVjdE1lcmdlID0gdXRpbHMub2JqZWN0TWVyZ2U7XG52YXIgdHJ1bmNhdGUgPSB1dGlscy50cnVuY2F0ZTtcbnZhciBvYmplY3RGcm96ZW4gPSB1dGlscy5vYmplY3RGcm96ZW47XG52YXIgaGFzS2V5ID0gdXRpbHMuaGFzS2V5O1xudmFyIGpvaW5SZWdFeHAgPSB1dGlscy5qb2luUmVnRXhwO1xudmFyIHVybGVuY29kZSA9IHV0aWxzLnVybGVuY29kZTtcbnZhciB1dWlkNCA9IHV0aWxzLnV1aWQ0O1xudmFyIGh0bWxUcmVlQXNTdHJpbmcgPSB1dGlscy5odG1sVHJlZUFzU3RyaW5nO1xudmFyIGlzU2FtZUV4Y2VwdGlvbiA9IHV0aWxzLmlzU2FtZUV4Y2VwdGlvbjtcbnZhciBpc1NhbWVTdGFja3RyYWNlID0gdXRpbHMuaXNTYW1lU3RhY2t0cmFjZTtcbnZhciBwYXJzZVVybCA9IHV0aWxzLnBhcnNlVXJsO1xudmFyIGZpbGwgPSB1dGlscy5maWxsO1xuXG52YXIgd3JhcENvbnNvbGVNZXRob2QgPSByZXF1aXJlKCcuL2NvbnNvbGUnKS53cmFwTWV0aG9kO1xuXG52YXIgZHNuS2V5cyA9ICdzb3VyY2UgcHJvdG9jb2wgdXNlciBwYXNzIGhvc3QgcG9ydCBwYXRoJy5zcGxpdCgnICcpLFxuICBkc25QYXR0ZXJuID0gL14oPzooXFx3Kyk6KT9cXC9cXC8oPzooXFx3KykoOlxcdyspP0ApPyhbXFx3XFwuLV0rKSg/OjooXFxkKykpPyhcXC8uKikvO1xuXG5mdW5jdGlvbiBub3coKSB7XG4gIHJldHVybiArbmV3IERhdGUoKTtcbn1cblxuLy8gVGhpcyBpcyB0byBiZSBkZWZlbnNpdmUgaW4gZW52aXJvbm1lbnRzIHdoZXJlIHdpbmRvdyBkb2VzIG5vdCBleGlzdCAoc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9nZXRzZW50cnkvcmF2ZW4tanMvcHVsbC83ODUpXG52YXIgX3dpbmRvdyA9XG4gIHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnXG4gICAgPyB3aW5kb3dcbiAgICA6IHR5cGVvZiBnbG9iYWwgIT09ICd1bmRlZmluZWQnID8gZ2xvYmFsIDogdHlwZW9mIHNlbGYgIT09ICd1bmRlZmluZWQnID8gc2VsZiA6IHt9O1xudmFyIF9kb2N1bWVudCA9IF93aW5kb3cuZG9jdW1lbnQ7XG52YXIgX25hdmlnYXRvciA9IF93aW5kb3cubmF2aWdhdG9yO1xuXG5mdW5jdGlvbiBrZWVwT3JpZ2luYWxDYWxsYmFjayhvcmlnaW5hbCwgY2FsbGJhY2spIHtcbiAgcmV0dXJuIGlzRnVuY3Rpb24oY2FsbGJhY2spXG4gICAgPyBmdW5jdGlvbihkYXRhKSB7XG4gICAgICAgIHJldHVybiBjYWxsYmFjayhkYXRhLCBvcmlnaW5hbCk7XG4gICAgICB9XG4gICAgOiBjYWxsYmFjaztcbn1cblxuLy8gRmlyc3QsIGNoZWNrIGZvciBKU09OIHN1cHBvcnRcbi8vIElmIHRoZXJlIGlzIG5vIEpTT04sIHdlIG5vLW9wIHRoZSBjb3JlIGZlYXR1cmVzIG9mIFJhdmVuXG4vLyBzaW5jZSBKU09OIGlzIHJlcXVpcmVkIHRvIGVuY29kZSB0aGUgcGF5bG9hZFxuZnVuY3Rpb24gUmF2ZW4oKSB7XG4gIHRoaXMuX2hhc0pTT04gPSAhISh0eXBlb2YgSlNPTiA9PT0gJ29iamVjdCcgJiYgSlNPTi5zdHJpbmdpZnkpO1xuICAvLyBSYXZlbiBjYW4gcnVuIGluIGNvbnRleHRzIHdoZXJlIHRoZXJlJ3Mgbm8gZG9jdW1lbnQgKHJlYWN0LW5hdGl2ZSlcbiAgdGhpcy5faGFzRG9jdW1lbnQgPSAhaXNVbmRlZmluZWQoX2RvY3VtZW50KTtcbiAgdGhpcy5faGFzTmF2aWdhdG9yID0gIWlzVW5kZWZpbmVkKF9uYXZpZ2F0b3IpO1xuICB0aGlzLl9sYXN0Q2FwdHVyZWRFeGNlcHRpb24gPSBudWxsO1xuICB0aGlzLl9sYXN0RGF0YSA9IG51bGw7XG4gIHRoaXMuX2xhc3RFdmVudElkID0gbnVsbDtcbiAgdGhpcy5fZ2xvYmFsU2VydmVyID0gbnVsbDtcbiAgdGhpcy5fZ2xvYmFsS2V5ID0gbnVsbDtcbiAgdGhpcy5fZ2xvYmFsUHJvamVjdCA9IG51bGw7XG4gIHRoaXMuX2dsb2JhbENvbnRleHQgPSB7fTtcbiAgdGhpcy5fZ2xvYmFsT3B0aW9ucyA9IHtcbiAgICBsb2dnZXI6ICdqYXZhc2NyaXB0JyxcbiAgICBpZ25vcmVFcnJvcnM6IFtdLFxuICAgIGlnbm9yZVVybHM6IFtdLFxuICAgIHdoaXRlbGlzdFVybHM6IFtdLFxuICAgIGluY2x1ZGVQYXRoczogW10sXG4gICAgY29sbGVjdFdpbmRvd0Vycm9yczogdHJ1ZSxcbiAgICBtYXhNZXNzYWdlTGVuZ3RoOiAwLFxuXG4gICAgLy8gQnkgZGVmYXVsdCwgdHJ1bmNhdGVzIFVSTCB2YWx1ZXMgdG8gMjUwIGNoYXJzXG4gICAgbWF4VXJsTGVuZ3RoOiAyNTAsXG4gICAgc3RhY2tUcmFjZUxpbWl0OiA1MCxcbiAgICBhdXRvQnJlYWRjcnVtYnM6IHRydWUsXG4gICAgaW5zdHJ1bWVudDogdHJ1ZSxcbiAgICBzYW1wbGVSYXRlOiAxXG4gIH07XG4gIHRoaXMuX2lnbm9yZU9uRXJyb3IgPSAwO1xuICB0aGlzLl9pc1JhdmVuSW5zdGFsbGVkID0gZmFsc2U7XG4gIHRoaXMuX29yaWdpbmFsRXJyb3JTdGFja1RyYWNlTGltaXQgPSBFcnJvci5zdGFja1RyYWNlTGltaXQ7XG4gIC8vIGNhcHR1cmUgcmVmZXJlbmNlcyB0byB3aW5kb3cuY29uc29sZSAqYW5kKiBhbGwgaXRzIG1ldGhvZHMgZmlyc3RcbiAgLy8gYmVmb3JlIHRoZSBjb25zb2xlIHBsdWdpbiBoYXMgYSBjaGFuY2UgdG8gbW9ua2V5IHBhdGNoXG4gIHRoaXMuX29yaWdpbmFsQ29uc29sZSA9IF93aW5kb3cuY29uc29sZSB8fCB7fTtcbiAgdGhpcy5fb3JpZ2luYWxDb25zb2xlTWV0aG9kcyA9IHt9O1xuICB0aGlzLl9wbHVnaW5zID0gW107XG4gIHRoaXMuX3N0YXJ0VGltZSA9IG5vdygpO1xuICB0aGlzLl93cmFwcGVkQnVpbHRJbnMgPSBbXTtcbiAgdGhpcy5fYnJlYWRjcnVtYnMgPSBbXTtcbiAgdGhpcy5fbGFzdENhcHR1cmVkRXZlbnQgPSBudWxsO1xuICB0aGlzLl9rZXlwcmVzc1RpbWVvdXQ7XG4gIHRoaXMuX2xvY2F0aW9uID0gX3dpbmRvdy5sb2NhdGlvbjtcbiAgdGhpcy5fbGFzdEhyZWYgPSB0aGlzLl9sb2NhdGlvbiAmJiB0aGlzLl9sb2NhdGlvbi5ocmVmO1xuICB0aGlzLl9yZXNldEJhY2tvZmYoKTtcblxuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgZ3VhcmQtZm9yLWluXG4gIGZvciAodmFyIG1ldGhvZCBpbiB0aGlzLl9vcmlnaW5hbENvbnNvbGUpIHtcbiAgICB0aGlzLl9vcmlnaW5hbENvbnNvbGVNZXRob2RzW21ldGhvZF0gPSB0aGlzLl9vcmlnaW5hbENvbnNvbGVbbWV0aG9kXTtcbiAgfVxufVxuXG4vKlxuICogVGhlIGNvcmUgUmF2ZW4gc2luZ2xldG9uXG4gKlxuICogQHRoaXMge1JhdmVufVxuICovXG5cblJhdmVuLnByb3RvdHlwZSA9IHtcbiAgLy8gSGFyZGNvZGUgdmVyc2lvbiBzdHJpbmcgc28gdGhhdCByYXZlbiBzb3VyY2UgY2FuIGJlIGxvYWRlZCBkaXJlY3RseSB2aWFcbiAgLy8gd2VicGFjayAodXNpbmcgYSBidWlsZCBzdGVwIGNhdXNlcyB3ZWJwYWNrICMxNjE3KS4gR3J1bnQgdmVyaWZpZXMgdGhhdFxuICAvLyB0aGlzIHZhbHVlIG1hdGNoZXMgcGFja2FnZS5qc29uIGR1cmluZyBidWlsZC5cbiAgLy8gICBTZWU6IGh0dHBzOi8vZ2l0aHViLmNvbS9nZXRzZW50cnkvcmF2ZW4tanMvaXNzdWVzLzQ2NVxuICBWRVJTSU9OOiAnMy4yMC4xJyxcblxuICBkZWJ1ZzogZmFsc2UsXG5cbiAgVHJhY2VLaXQ6IFRyYWNlS2l0LCAvLyBhbGlhcyB0byBUcmFjZUtpdFxuXG4gIC8qXG4gICAgICogQ29uZmlndXJlIFJhdmVuIHdpdGggYSBEU04gYW5kIGV4dHJhIG9wdGlvbnNcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7c3RyaW5nfSBkc24gVGhlIHB1YmxpYyBTZW50cnkgRFNOXG4gICAgICogQHBhcmFtIHtvYmplY3R9IG9wdGlvbnMgU2V0IG9mIGdsb2JhbCBvcHRpb25zIFtvcHRpb25hbF1cbiAgICAgKiBAcmV0dXJuIHtSYXZlbn1cbiAgICAgKi9cbiAgY29uZmlnOiBmdW5jdGlvbihkc24sIG9wdGlvbnMpIHtcbiAgICB2YXIgc2VsZiA9IHRoaXM7XG5cbiAgICBpZiAoc2VsZi5fZ2xvYmFsU2VydmVyKSB7XG4gICAgICB0aGlzLl9sb2dEZWJ1ZygnZXJyb3InLCAnRXJyb3I6IFJhdmVuIGhhcyBhbHJlYWR5IGJlZW4gY29uZmlndXJlZCcpO1xuICAgICAgcmV0dXJuIHNlbGY7XG4gICAgfVxuICAgIGlmICghZHNuKSByZXR1cm4gc2VsZjtcblxuICAgIHZhciBnbG9iYWxPcHRpb25zID0gc2VsZi5fZ2xvYmFsT3B0aW9ucztcblxuICAgIC8vIG1lcmdlIGluIG9wdGlvbnNcbiAgICBpZiAob3B0aW9ucykge1xuICAgICAgZWFjaChvcHRpb25zLCBmdW5jdGlvbihrZXksIHZhbHVlKSB7XG4gICAgICAgIC8vIHRhZ3MgYW5kIGV4dHJhIGFyZSBzcGVjaWFsIGFuZCBuZWVkIHRvIGJlIHB1dCBpbnRvIGNvbnRleHRcbiAgICAgICAgaWYgKGtleSA9PT0gJ3RhZ3MnIHx8IGtleSA9PT0gJ2V4dHJhJyB8fCBrZXkgPT09ICd1c2VyJykge1xuICAgICAgICAgIHNlbGYuX2dsb2JhbENvbnRleHRba2V5XSA9IHZhbHVlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGdsb2JhbE9wdGlvbnNba2V5XSA9IHZhbHVlO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBzZWxmLnNldERTTihkc24pO1xuXG4gICAgLy8gXCJTY3JpcHQgZXJyb3IuXCIgaXMgaGFyZCBjb2RlZCBpbnRvIGJyb3dzZXJzIGZvciBlcnJvcnMgdGhhdCBpdCBjYW4ndCByZWFkLlxuICAgIC8vIHRoaXMgaXMgdGhlIHJlc3VsdCBvZiBhIHNjcmlwdCBiZWluZyBwdWxsZWQgaW4gZnJvbSBhbiBleHRlcm5hbCBkb21haW4gYW5kIENPUlMuXG4gICAgZ2xvYmFsT3B0aW9ucy5pZ25vcmVFcnJvcnMucHVzaCgvXlNjcmlwdCBlcnJvclxcLj8kLyk7XG4gICAgZ2xvYmFsT3B0aW9ucy5pZ25vcmVFcnJvcnMucHVzaCgvXkphdmFzY3JpcHQgZXJyb3I6IFNjcmlwdCBlcnJvclxcLj8gb24gbGluZSAwJC8pO1xuXG4gICAgLy8gam9pbiByZWdleHAgcnVsZXMgaW50byBvbmUgYmlnIHJ1bGVcbiAgICBnbG9iYWxPcHRpb25zLmlnbm9yZUVycm9ycyA9IGpvaW5SZWdFeHAoZ2xvYmFsT3B0aW9ucy5pZ25vcmVFcnJvcnMpO1xuICAgIGdsb2JhbE9wdGlvbnMuaWdub3JlVXJscyA9IGdsb2JhbE9wdGlvbnMuaWdub3JlVXJscy5sZW5ndGhcbiAgICAgID8gam9pblJlZ0V4cChnbG9iYWxPcHRpb25zLmlnbm9yZVVybHMpXG4gICAgICA6IGZhbHNlO1xuICAgIGdsb2JhbE9wdGlvbnMud2hpdGVsaXN0VXJscyA9IGdsb2JhbE9wdGlvbnMud2hpdGVsaXN0VXJscy5sZW5ndGhcbiAgICAgID8gam9pblJlZ0V4cChnbG9iYWxPcHRpb25zLndoaXRlbGlzdFVybHMpXG4gICAgICA6IGZhbHNlO1xuICAgIGdsb2JhbE9wdGlvbnMuaW5jbHVkZVBhdGhzID0gam9pblJlZ0V4cChnbG9iYWxPcHRpb25zLmluY2x1ZGVQYXRocyk7XG4gICAgZ2xvYmFsT3B0aW9ucy5tYXhCcmVhZGNydW1icyA9IE1hdGgubWF4KFxuICAgICAgMCxcbiAgICAgIE1hdGgubWluKGdsb2JhbE9wdGlvbnMubWF4QnJlYWRjcnVtYnMgfHwgMTAwLCAxMDApXG4gICAgKTsgLy8gZGVmYXVsdCBhbmQgaGFyZCBsaW1pdCBpcyAxMDBcblxuICAgIHZhciBhdXRvQnJlYWRjcnVtYkRlZmF1bHRzID0ge1xuICAgICAgeGhyOiB0cnVlLFxuICAgICAgY29uc29sZTogdHJ1ZSxcbiAgICAgIGRvbTogdHJ1ZSxcbiAgICAgIGxvY2F0aW9uOiB0cnVlLFxuICAgICAgc2VudHJ5OiB0cnVlXG4gICAgfTtcblxuICAgIHZhciBhdXRvQnJlYWRjcnVtYnMgPSBnbG9iYWxPcHRpb25zLmF1dG9CcmVhZGNydW1icztcbiAgICBpZiAoe30udG9TdHJpbmcuY2FsbChhdXRvQnJlYWRjcnVtYnMpID09PSAnW29iamVjdCBPYmplY3RdJykge1xuICAgICAgYXV0b0JyZWFkY3J1bWJzID0gb2JqZWN0TWVyZ2UoYXV0b0JyZWFkY3J1bWJEZWZhdWx0cywgYXV0b0JyZWFkY3J1bWJzKTtcbiAgICB9IGVsc2UgaWYgKGF1dG9CcmVhZGNydW1icyAhPT0gZmFsc2UpIHtcbiAgICAgIGF1dG9CcmVhZGNydW1icyA9IGF1dG9CcmVhZGNydW1iRGVmYXVsdHM7XG4gICAgfVxuICAgIGdsb2JhbE9wdGlvbnMuYXV0b0JyZWFkY3J1bWJzID0gYXV0b0JyZWFkY3J1bWJzO1xuXG4gICAgdmFyIGluc3RydW1lbnREZWZhdWx0cyA9IHtcbiAgICAgIHRyeUNhdGNoOiB0cnVlXG4gICAgfTtcblxuICAgIHZhciBpbnN0cnVtZW50ID0gZ2xvYmFsT3B0aW9ucy5pbnN0cnVtZW50O1xuICAgIGlmICh7fS50b1N0cmluZy5jYWxsKGluc3RydW1lbnQpID09PSAnW29iamVjdCBPYmplY3RdJykge1xuICAgICAgaW5zdHJ1bWVudCA9IG9iamVjdE1lcmdlKGluc3RydW1lbnREZWZhdWx0cywgaW5zdHJ1bWVudCk7XG4gICAgfSBlbHNlIGlmIChpbnN0cnVtZW50ICE9PSBmYWxzZSkge1xuICAgICAgaW5zdHJ1bWVudCA9IGluc3RydW1lbnREZWZhdWx0cztcbiAgICB9XG4gICAgZ2xvYmFsT3B0aW9ucy5pbnN0cnVtZW50ID0gaW5zdHJ1bWVudDtcblxuICAgIFRyYWNlS2l0LmNvbGxlY3RXaW5kb3dFcnJvcnMgPSAhIWdsb2JhbE9wdGlvbnMuY29sbGVjdFdpbmRvd0Vycm9ycztcblxuICAgIC8vIHJldHVybiBmb3IgY2hhaW5pbmdcbiAgICByZXR1cm4gc2VsZjtcbiAgfSxcblxuICAvKlxuICAgICAqIEluc3RhbGxzIGEgZ2xvYmFsIHdpbmRvdy5vbmVycm9yIGVycm9yIGhhbmRsZXJcbiAgICAgKiB0byBjYXB0dXJlIGFuZCByZXBvcnQgdW5jYXVnaHQgZXhjZXB0aW9ucy5cbiAgICAgKiBBdCB0aGlzIHBvaW50LCBpbnN0YWxsKCkgaXMgcmVxdWlyZWQgdG8gYmUgY2FsbGVkIGR1ZVxuICAgICAqIHRvIHRoZSB3YXkgVHJhY2VLaXQgaXMgc2V0IHVwLlxuICAgICAqXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIGluc3RhbGw6IGZ1bmN0aW9uKCkge1xuICAgIHZhciBzZWxmID0gdGhpcztcbiAgICBpZiAoc2VsZi5pc1NldHVwKCkgJiYgIXNlbGYuX2lzUmF2ZW5JbnN0YWxsZWQpIHtcbiAgICAgIFRyYWNlS2l0LnJlcG9ydC5zdWJzY3JpYmUoZnVuY3Rpb24oKSB7XG4gICAgICAgIHNlbGYuX2hhbmRsZU9uRXJyb3JTdGFja0luZm8uYXBwbHkoc2VsZiwgYXJndW1lbnRzKTtcbiAgICAgIH0pO1xuXG4gICAgICBzZWxmLl9wYXRjaEZ1bmN0aW9uVG9TdHJpbmcoKTtcblxuICAgICAgaWYgKHNlbGYuX2dsb2JhbE9wdGlvbnMuaW5zdHJ1bWVudCAmJiBzZWxmLl9nbG9iYWxPcHRpb25zLmluc3RydW1lbnQudHJ5Q2F0Y2gpIHtcbiAgICAgICAgc2VsZi5faW5zdHJ1bWVudFRyeUNhdGNoKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChzZWxmLl9nbG9iYWxPcHRpb25zLmF1dG9CcmVhZGNydW1icykgc2VsZi5faW5zdHJ1bWVudEJyZWFkY3J1bWJzKCk7XG5cbiAgICAgIC8vIEluc3RhbGwgYWxsIG9mIHRoZSBwbHVnaW5zXG4gICAgICBzZWxmLl9kcmFpblBsdWdpbnMoKTtcblxuICAgICAgc2VsZi5faXNSYXZlbkluc3RhbGxlZCA9IHRydWU7XG4gICAgfVxuXG4gICAgRXJyb3Iuc3RhY2tUcmFjZUxpbWl0ID0gc2VsZi5fZ2xvYmFsT3B0aW9ucy5zdGFja1RyYWNlTGltaXQ7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBTZXQgdGhlIERTTiAoY2FuIGJlIGNhbGxlZCBtdWx0aXBsZSB0aW1lIHVubGlrZSBjb25maWcpXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge3N0cmluZ30gZHNuIFRoZSBwdWJsaWMgU2VudHJ5IERTTlxuICAgICAqL1xuICBzZXREU046IGZ1bmN0aW9uKGRzbikge1xuICAgIHZhciBzZWxmID0gdGhpcyxcbiAgICAgIHVyaSA9IHNlbGYuX3BhcnNlRFNOKGRzbiksXG4gICAgICBsYXN0U2xhc2ggPSB1cmkucGF0aC5sYXN0SW5kZXhPZignLycpLFxuICAgICAgcGF0aCA9IHVyaS5wYXRoLnN1YnN0cigxLCBsYXN0U2xhc2gpO1xuXG4gICAgc2VsZi5fZHNuID0gZHNuO1xuICAgIHNlbGYuX2dsb2JhbEtleSA9IHVyaS51c2VyO1xuICAgIHNlbGYuX2dsb2JhbFNlY3JldCA9IHVyaS5wYXNzICYmIHVyaS5wYXNzLnN1YnN0cigxKTtcbiAgICBzZWxmLl9nbG9iYWxQcm9qZWN0ID0gdXJpLnBhdGguc3Vic3RyKGxhc3RTbGFzaCArIDEpO1xuXG4gICAgc2VsZi5fZ2xvYmFsU2VydmVyID0gc2VsZi5fZ2V0R2xvYmFsU2VydmVyKHVyaSk7XG5cbiAgICBzZWxmLl9nbG9iYWxFbmRwb2ludCA9XG4gICAgICBzZWxmLl9nbG9iYWxTZXJ2ZXIgKyAnLycgKyBwYXRoICsgJ2FwaS8nICsgc2VsZi5fZ2xvYmFsUHJvamVjdCArICcvc3RvcmUvJztcblxuICAgIC8vIFJlc2V0IGJhY2tvZmYgc3RhdGUgc2luY2Ugd2UgbWF5IGJlIHBvaW50aW5nIGF0IGFcbiAgICAvLyBuZXcgcHJvamVjdC9zZXJ2ZXJcbiAgICB0aGlzLl9yZXNldEJhY2tvZmYoKTtcbiAgfSxcblxuICAvKlxuICAgICAqIFdyYXAgY29kZSB3aXRoaW4gYSBjb250ZXh0IHNvIFJhdmVuIGNhbiBjYXB0dXJlIGVycm9yc1xuICAgICAqIHJlbGlhYmx5IGFjcm9zcyBkb21haW5zIHRoYXQgaXMgZXhlY3V0ZWQgaW1tZWRpYXRlbHkuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge29iamVjdH0gb3B0aW9ucyBBIHNwZWNpZmljIHNldCBvZiBvcHRpb25zIGZvciB0aGlzIGNvbnRleHQgW29wdGlvbmFsXVxuICAgICAqIEBwYXJhbSB7ZnVuY3Rpb259IGZ1bmMgVGhlIGNhbGxiYWNrIHRvIGJlIGltbWVkaWF0ZWx5IGV4ZWN1dGVkIHdpdGhpbiB0aGUgY29udGV4dFxuICAgICAqIEBwYXJhbSB7YXJyYXl9IGFyZ3MgQW4gYXJyYXkgb2YgYXJndW1lbnRzIHRvIGJlIGNhbGxlZCB3aXRoIHRoZSBjYWxsYmFjayBbb3B0aW9uYWxdXG4gICAgICovXG4gIGNvbnRleHQ6IGZ1bmN0aW9uKG9wdGlvbnMsIGZ1bmMsIGFyZ3MpIHtcbiAgICBpZiAoaXNGdW5jdGlvbihvcHRpb25zKSkge1xuICAgICAgYXJncyA9IGZ1bmMgfHwgW107XG4gICAgICBmdW5jID0gb3B0aW9ucztcbiAgICAgIG9wdGlvbnMgPSB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMud3JhcChvcHRpb25zLCBmdW5jKS5hcHBseSh0aGlzLCBhcmdzKTtcbiAgfSxcblxuICAvKlxuICAgICAqIFdyYXAgY29kZSB3aXRoaW4gYSBjb250ZXh0IGFuZCByZXR1cm5zIGJhY2sgYSBuZXcgZnVuY3Rpb24gdG8gYmUgZXhlY3V0ZWRcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7b2JqZWN0fSBvcHRpb25zIEEgc3BlY2lmaWMgc2V0IG9mIG9wdGlvbnMgZm9yIHRoaXMgY29udGV4dCBbb3B0aW9uYWxdXG4gICAgICogQHBhcmFtIHtmdW5jdGlvbn0gZnVuYyBUaGUgZnVuY3Rpb24gdG8gYmUgd3JhcHBlZCBpbiBhIG5ldyBjb250ZXh0XG4gICAgICogQHBhcmFtIHtmdW5jdGlvbn0gZnVuYyBBIGZ1bmN0aW9uIHRvIGNhbGwgYmVmb3JlIHRoZSB0cnkvY2F0Y2ggd3JhcHBlciBbb3B0aW9uYWwsIHByaXZhdGVdXG4gICAgICogQHJldHVybiB7ZnVuY3Rpb259IFRoZSBuZXdseSB3cmFwcGVkIGZ1bmN0aW9ucyB3aXRoIGEgY29udGV4dFxuICAgICAqL1xuICB3cmFwOiBmdW5jdGlvbihvcHRpb25zLCBmdW5jLCBfYmVmb3JlKSB7XG4gICAgdmFyIHNlbGYgPSB0aGlzO1xuICAgIC8vIDEgYXJndW1lbnQgaGFzIGJlZW4gcGFzc2VkLCBhbmQgaXQncyBub3QgYSBmdW5jdGlvblxuICAgIC8vIHNvIGp1c3QgcmV0dXJuIGl0XG4gICAgaWYgKGlzVW5kZWZpbmVkKGZ1bmMpICYmICFpc0Z1bmN0aW9uKG9wdGlvbnMpKSB7XG4gICAgICByZXR1cm4gb3B0aW9ucztcbiAgICB9XG5cbiAgICAvLyBvcHRpb25zIGlzIG9wdGlvbmFsXG4gICAgaWYgKGlzRnVuY3Rpb24ob3B0aW9ucykpIHtcbiAgICAgIGZ1bmMgPSBvcHRpb25zO1xuICAgICAgb3B0aW9ucyA9IHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICAvLyBBdCB0aGlzIHBvaW50LCB3ZSd2ZSBwYXNzZWQgYWxvbmcgMiBhcmd1bWVudHMsIGFuZCB0aGUgc2Vjb25kIG9uZVxuICAgIC8vIGlzIG5vdCBhIGZ1bmN0aW9uIGVpdGhlciwgc28gd2UnbGwganVzdCByZXR1cm4gdGhlIHNlY29uZCBhcmd1bWVudC5cbiAgICBpZiAoIWlzRnVuY3Rpb24oZnVuYykpIHtcbiAgICAgIHJldHVybiBmdW5jO1xuICAgIH1cblxuICAgIC8vIFdlIGRvbid0IHdhbm5hIHdyYXAgaXQgdHdpY2UhXG4gICAgdHJ5IHtcbiAgICAgIGlmIChmdW5jLl9fcmF2ZW5fXykge1xuICAgICAgICByZXR1cm4gZnVuYztcbiAgICAgIH1cblxuICAgICAgLy8gSWYgdGhpcyBoYXMgYWxyZWFkeSBiZWVuIHdyYXBwZWQgaW4gdGhlIHBhc3QsIHJldHVybiB0aGF0XG4gICAgICBpZiAoZnVuYy5fX3JhdmVuX3dyYXBwZXJfXykge1xuICAgICAgICByZXR1cm4gZnVuYy5fX3JhdmVuX3dyYXBwZXJfXztcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAvLyBKdXN0IGFjY2Vzc2luZyBjdXN0b20gcHJvcHMgaW4gc29tZSBTZWxlbml1bSBlbnZpcm9ubWVudHNcbiAgICAgIC8vIGNhbiBjYXVzZSBhIFwiUGVybWlzc2lvbiBkZW5pZWRcIiBleGNlcHRpb24gKHNlZSByYXZlbi1qcyM0OTUpLlxuICAgICAgLy8gQmFpbCBvbiB3cmFwcGluZyBhbmQgcmV0dXJuIHRoZSBmdW5jdGlvbiBhcy1pcyAoZGVmZXJzIHRvIHdpbmRvdy5vbmVycm9yKS5cbiAgICAgIHJldHVybiBmdW5jO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHdyYXBwZWQoKSB7XG4gICAgICB2YXIgYXJncyA9IFtdLFxuICAgICAgICBpID0gYXJndW1lbnRzLmxlbmd0aCxcbiAgICAgICAgZGVlcCA9ICFvcHRpb25zIHx8IChvcHRpb25zICYmIG9wdGlvbnMuZGVlcCAhPT0gZmFsc2UpO1xuXG4gICAgICBpZiAoX2JlZm9yZSAmJiBpc0Z1bmN0aW9uKF9iZWZvcmUpKSB7XG4gICAgICAgIF9iZWZvcmUuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbiAgICAgIH1cblxuICAgICAgLy8gUmVjdXJzaXZlbHkgd3JhcCBhbGwgb2YgYSBmdW5jdGlvbidzIGFyZ3VtZW50cyB0aGF0IGFyZVxuICAgICAgLy8gZnVuY3Rpb25zIHRoZW1zZWx2ZXMuXG4gICAgICB3aGlsZSAoaS0tKSBhcmdzW2ldID0gZGVlcCA/IHNlbGYud3JhcChvcHRpb25zLCBhcmd1bWVudHNbaV0pIDogYXJndW1lbnRzW2ldO1xuXG4gICAgICB0cnkge1xuICAgICAgICAvLyBBdHRlbXB0IHRvIGludm9rZSB1c2VyLWxhbmQgZnVuY3Rpb25cbiAgICAgICAgLy8gTk9URTogSWYgeW91IGFyZSBhIFNlbnRyeSB1c2VyLCBhbmQgeW91IGFyZSBzZWVpbmcgdGhpcyBzdGFjayBmcmFtZSwgaXRcbiAgICAgICAgLy8gICAgICAgbWVhbnMgUmF2ZW4gY2F1Z2h0IGFuIGVycm9yIGludm9raW5nIHlvdXIgYXBwbGljYXRpb24gY29kZS4gVGhpcyBpc1xuICAgICAgICAvLyAgICAgICBleHBlY3RlZCBiZWhhdmlvciBhbmQgTk9UIGluZGljYXRpdmUgb2YgYSBidWcgd2l0aCBSYXZlbi5qcy5cbiAgICAgICAgcmV0dXJuIGZ1bmMuYXBwbHkodGhpcywgYXJncyk7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHNlbGYuX2lnbm9yZU5leHRPbkVycm9yKCk7XG4gICAgICAgIHNlbGYuY2FwdHVyZUV4Y2VwdGlvbihlLCBvcHRpb25zKTtcbiAgICAgICAgdGhyb3cgZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBjb3B5IG92ZXIgcHJvcGVydGllcyBvZiB0aGUgb2xkIGZ1bmN0aW9uXG4gICAgZm9yICh2YXIgcHJvcGVydHkgaW4gZnVuYykge1xuICAgICAgaWYgKGhhc0tleShmdW5jLCBwcm9wZXJ0eSkpIHtcbiAgICAgICAgd3JhcHBlZFtwcm9wZXJ0eV0gPSBmdW5jW3Byb3BlcnR5XTtcbiAgICAgIH1cbiAgICB9XG4gICAgd3JhcHBlZC5wcm90b3R5cGUgPSBmdW5jLnByb3RvdHlwZTtcblxuICAgIGZ1bmMuX19yYXZlbl93cmFwcGVyX18gPSB3cmFwcGVkO1xuICAgIC8vIFNpZ25hbCB0aGF0IHRoaXMgZnVuY3Rpb24gaGFzIGJlZW4gd3JhcHBlZC9maWxsZWQgYWxyZWFkeVxuICAgIC8vIGZvciBib3RoIGRlYnVnZ2luZyBhbmQgdG8gcHJldmVudCBpdCB0byBiZWluZyB3cmFwcGVkL2ZpbGxlZCB0d2ljZVxuICAgIHdyYXBwZWQuX19yYXZlbl9fID0gdHJ1ZTtcbiAgICB3cmFwcGVkLl9fb3JpZ19fID0gZnVuYztcblxuICAgIHJldHVybiB3cmFwcGVkO1xuICB9LFxuXG4gIC8qXG4gICAgICogVW5pbnN0YWxscyB0aGUgZ2xvYmFsIGVycm9yIGhhbmRsZXIuXG4gICAgICpcbiAgICAgKiBAcmV0dXJuIHtSYXZlbn1cbiAgICAgKi9cbiAgdW5pbnN0YWxsOiBmdW5jdGlvbigpIHtcbiAgICBUcmFjZUtpdC5yZXBvcnQudW5pbnN0YWxsKCk7XG5cbiAgICB0aGlzLl91bnBhdGNoRnVuY3Rpb25Ub1N0cmluZygpO1xuICAgIHRoaXMuX3Jlc3RvcmVCdWlsdElucygpO1xuXG4gICAgRXJyb3Iuc3RhY2tUcmFjZUxpbWl0ID0gdGhpcy5fb3JpZ2luYWxFcnJvclN0YWNrVHJhY2VMaW1pdDtcbiAgICB0aGlzLl9pc1JhdmVuSW5zdGFsbGVkID0gZmFsc2U7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfSxcblxuICAvKlxuICAgICAqIE1hbnVhbGx5IGNhcHR1cmUgYW4gZXhjZXB0aW9uIGFuZCBzZW5kIGl0IG92ZXIgdG8gU2VudHJ5XG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2Vycm9yfSBleCBBbiBleGNlcHRpb24gdG8gYmUgbG9nZ2VkXG4gICAgICogQHBhcmFtIHtvYmplY3R9IG9wdGlvbnMgQSBzcGVjaWZpYyBzZXQgb2Ygb3B0aW9ucyBmb3IgdGhpcyBlcnJvciBbb3B0aW9uYWxdXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIGNhcHR1cmVFeGNlcHRpb246IGZ1bmN0aW9uKGV4LCBvcHRpb25zKSB7XG4gICAgLy8gQ2FzZXMgZm9yIHNlbmRpbmcgZXggYXMgYSBtZXNzYWdlLCByYXRoZXIgdGhhbiBhbiBleGNlcHRpb25cbiAgICB2YXIgaXNOb3RFcnJvciA9ICFpc0Vycm9yKGV4KTtcbiAgICB2YXIgaXNOb3RFcnJvckV2ZW50ID0gIWlzRXJyb3JFdmVudChleCk7XG4gICAgdmFyIGlzRXJyb3JFdmVudFdpdGhvdXRFcnJvciA9IGlzRXJyb3JFdmVudChleCkgJiYgIWV4LmVycm9yO1xuXG4gICAgaWYgKChpc05vdEVycm9yICYmIGlzTm90RXJyb3JFdmVudCkgfHwgaXNFcnJvckV2ZW50V2l0aG91dEVycm9yKSB7XG4gICAgICByZXR1cm4gdGhpcy5jYXB0dXJlTWVzc2FnZShcbiAgICAgICAgZXgsXG4gICAgICAgIG9iamVjdE1lcmdlKFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIHRyaW1IZWFkRnJhbWVzOiAxLFxuICAgICAgICAgICAgc3RhY2t0cmFjZTogdHJ1ZSAvLyBpZiB3ZSBmYWxsIGJhY2sgdG8gY2FwdHVyZU1lc3NhZ2UsIGRlZmF1bHQgdG8gYXR0ZW1wdGluZyBhIG5ldyB0cmFjZVxuICAgICAgICAgIH0sXG4gICAgICAgICAgb3B0aW9uc1xuICAgICAgICApXG4gICAgICApO1xuICAgIH1cblxuICAgIC8vIEdldCBhY3R1YWwgRXJyb3IgZnJvbSBFcnJvckV2ZW50XG4gICAgaWYgKGlzRXJyb3JFdmVudChleCkpIGV4ID0gZXguZXJyb3I7XG5cbiAgICAvLyBTdG9yZSB0aGUgcmF3IGV4Y2VwdGlvbiBvYmplY3QgZm9yIHBvdGVudGlhbCBkZWJ1Z2dpbmcgYW5kIGludHJvc3BlY3Rpb25cbiAgICB0aGlzLl9sYXN0Q2FwdHVyZWRFeGNlcHRpb24gPSBleDtcblxuICAgIC8vIFRyYWNlS2l0LnJlcG9ydCB3aWxsIHJlLXJhaXNlIGFueSBleGNlcHRpb24gcGFzc2VkIHRvIGl0LFxuICAgIC8vIHdoaWNoIG1lYW5zIHlvdSBoYXZlIHRvIHdyYXAgaXQgaW4gdHJ5L2NhdGNoLiBJbnN0ZWFkLCB3ZVxuICAgIC8vIGNhbiB3cmFwIGl0IGhlcmUgYW5kIG9ubHkgcmUtcmFpc2UgaWYgVHJhY2VLaXQucmVwb3J0XG4gICAgLy8gcmFpc2VzIGFuIGV4Y2VwdGlvbiBkaWZmZXJlbnQgZnJvbSB0aGUgb25lIHdlIGFza2VkIHRvXG4gICAgLy8gcmVwb3J0IG9uLlxuICAgIHRyeSB7XG4gICAgICB2YXIgc3RhY2sgPSBUcmFjZUtpdC5jb21wdXRlU3RhY2tUcmFjZShleCk7XG4gICAgICB0aGlzLl9oYW5kbGVTdGFja0luZm8oc3RhY2ssIG9wdGlvbnMpO1xuICAgIH0gY2F0Y2ggKGV4MSkge1xuICAgICAgaWYgKGV4ICE9PSBleDEpIHtcbiAgICAgICAgdGhyb3cgZXgxO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIC8qXG4gICAgICogTWFudWFsbHkgc2VuZCBhIG1lc3NhZ2UgdG8gU2VudHJ5XG4gICAgICpcbiAgICAgKiBAcGFyYW0ge3N0cmluZ30gbXNnIEEgcGxhaW4gbWVzc2FnZSB0byBiZSBjYXB0dXJlZCBpbiBTZW50cnlcbiAgICAgKiBAcGFyYW0ge29iamVjdH0gb3B0aW9ucyBBIHNwZWNpZmljIHNldCBvZiBvcHRpb25zIGZvciB0aGlzIG1lc3NhZ2UgW29wdGlvbmFsXVxuICAgICAqIEByZXR1cm4ge1JhdmVufVxuICAgICAqL1xuICBjYXB0dXJlTWVzc2FnZTogZnVuY3Rpb24obXNnLCBvcHRpb25zKSB7XG4gICAgLy8gY29uZmlnKCkgYXV0b21hZ2ljYWxseSBjb252ZXJ0cyBpZ25vcmVFcnJvcnMgZnJvbSBhIGxpc3QgdG8gYSBSZWdFeHAgc28gd2UgbmVlZCB0byB0ZXN0IGZvciBhblxuICAgIC8vIGVhcmx5IGNhbGw7IHdlJ2xsIGVycm9yIG9uIHRoZSBzaWRlIG9mIGxvZ2dpbmcgYW55dGhpbmcgY2FsbGVkIGJlZm9yZSBjb25maWd1cmF0aW9uIHNpbmNlIGl0J3NcbiAgICAvLyBwcm9iYWJseSBzb21ldGhpbmcgeW91IHNob3VsZCBzZWU6XG4gICAgaWYgKFxuICAgICAgISF0aGlzLl9nbG9iYWxPcHRpb25zLmlnbm9yZUVycm9ycy50ZXN0ICYmXG4gICAgICB0aGlzLl9nbG9iYWxPcHRpb25zLmlnbm9yZUVycm9ycy50ZXN0KG1zZylcbiAgICApIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcblxuICAgIHZhciBkYXRhID0gb2JqZWN0TWVyZ2UoXG4gICAgICB7XG4gICAgICAgIG1lc3NhZ2U6IG1zZyArICcnIC8vIE1ha2Ugc3VyZSBpdCdzIGFjdHVhbGx5IGEgc3RyaW5nXG4gICAgICB9LFxuICAgICAgb3B0aW9uc1xuICAgICk7XG5cbiAgICB2YXIgZXg7XG4gICAgLy8gR2VuZXJhdGUgYSBcInN5bnRoZXRpY1wiIHN0YWNrIHRyYWNlIGZyb20gdGhpcyBwb2ludC5cbiAgICAvLyBOT1RFOiBJZiB5b3UgYXJlIGEgU2VudHJ5IHVzZXIsIGFuZCB5b3UgYXJlIHNlZWluZyB0aGlzIHN0YWNrIGZyYW1lLCBpdCBpcyBOT1QgaW5kaWNhdGl2ZVxuICAgIC8vICAgICAgIG9mIGEgYnVnIHdpdGggUmF2ZW4uanMuIFNlbnRyeSBnZW5lcmF0ZXMgc3ludGhldGljIHRyYWNlcyBlaXRoZXIgYnkgY29uZmlndXJhdGlvbixcbiAgICAvLyAgICAgICBvciBpZiBpdCBjYXRjaGVzIGEgdGhyb3duIG9iamVjdCB3aXRob3V0IGEgXCJzdGFja1wiIHByb3BlcnR5LlxuICAgIHRyeSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IobXNnKTtcbiAgICB9IGNhdGNoIChleDEpIHtcbiAgICAgIGV4ID0gZXgxO1xuICAgIH1cblxuICAgIC8vIG51bGwgZXhjZXB0aW9uIG5hbWUgc28gYEVycm9yYCBpc24ndCBwcmVmaXhlZCB0byBtc2dcbiAgICBleC5uYW1lID0gbnVsbDtcbiAgICB2YXIgc3RhY2sgPSBUcmFjZUtpdC5jb21wdXRlU3RhY2tUcmFjZShleCk7XG5cbiAgICAvLyBzdGFja1swXSBpcyBgdGhyb3cgbmV3IEVycm9yKG1zZylgIGNhbGwgaXRzZWxmLCB3ZSBhcmUgaW50ZXJlc3RlZCBpbiB0aGUgZnJhbWUgdGhhdCB3YXMganVzdCBiZWZvcmUgdGhhdCwgc3RhY2tbMV1cbiAgICB2YXIgaW5pdGlhbENhbGwgPSBpc0FycmF5KHN0YWNrLnN0YWNrKSAmJiBzdGFjay5zdGFja1sxXTtcbiAgICB2YXIgZmlsZXVybCA9IChpbml0aWFsQ2FsbCAmJiBpbml0aWFsQ2FsbC51cmwpIHx8ICcnO1xuXG4gICAgaWYgKFxuICAgICAgISF0aGlzLl9nbG9iYWxPcHRpb25zLmlnbm9yZVVybHMudGVzdCAmJlxuICAgICAgdGhpcy5fZ2xvYmFsT3B0aW9ucy5pZ25vcmVVcmxzLnRlc3QoZmlsZXVybClcbiAgICApIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAoXG4gICAgICAhIXRoaXMuX2dsb2JhbE9wdGlvbnMud2hpdGVsaXN0VXJscy50ZXN0ICYmXG4gICAgICAhdGhpcy5fZ2xvYmFsT3B0aW9ucy53aGl0ZWxpc3RVcmxzLnRlc3QoZmlsZXVybClcbiAgICApIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5fZ2xvYmFsT3B0aW9ucy5zdGFja3RyYWNlIHx8IChvcHRpb25zICYmIG9wdGlvbnMuc3RhY2t0cmFjZSkpIHtcbiAgICAgIG9wdGlvbnMgPSBvYmplY3RNZXJnZShcbiAgICAgICAge1xuICAgICAgICAgIC8vIGZpbmdlcnByaW50IG9uIG1zZywgbm90IHN0YWNrIHRyYWNlIChsZWdhY3kgYmVoYXZpb3IsIGNvdWxkIGJlXG4gICAgICAgICAgLy8gcmV2aXNpdGVkKVxuICAgICAgICAgIGZpbmdlcnByaW50OiBtc2csXG4gICAgICAgICAgLy8gc2luY2Ugd2Uga25vdyB0aGlzIGlzIGEgc3ludGhldGljIHRyYWNlLCB0aGUgdG9wIE4tbW9zdCBmcmFtZXNcbiAgICAgICAgICAvLyBNVVNUIGJlIGZyb20gUmF2ZW4uanMsIHNvIG1hcmsgdGhlbSBhcyBpbl9hcHAgbGF0ZXIgYnkgc2V0dGluZ1xuICAgICAgICAgIC8vIHRyaW1IZWFkRnJhbWVzXG4gICAgICAgICAgdHJpbUhlYWRGcmFtZXM6IChvcHRpb25zLnRyaW1IZWFkRnJhbWVzIHx8IDApICsgMVxuICAgICAgICB9LFxuICAgICAgICBvcHRpb25zXG4gICAgICApO1xuXG4gICAgICB2YXIgZnJhbWVzID0gdGhpcy5fcHJlcGFyZUZyYW1lcyhzdGFjaywgb3B0aW9ucyk7XG4gICAgICBkYXRhLnN0YWNrdHJhY2UgPSB7XG4gICAgICAgIC8vIFNlbnRyeSBleHBlY3RzIGZyYW1lcyBvbGRlc3QgdG8gbmV3ZXN0XG4gICAgICAgIGZyYW1lczogZnJhbWVzLnJldmVyc2UoKVxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBGaXJlIGF3YXkhXG4gICAgdGhpcy5fc2VuZChkYXRhKTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIGNhcHR1cmVCcmVhZGNydW1iOiBmdW5jdGlvbihvYmopIHtcbiAgICB2YXIgY3J1bWIgPSBvYmplY3RNZXJnZShcbiAgICAgIHtcbiAgICAgICAgdGltZXN0YW1wOiBub3coKSAvIDEwMDBcbiAgICAgIH0sXG4gICAgICBvYmpcbiAgICApO1xuXG4gICAgaWYgKGlzRnVuY3Rpb24odGhpcy5fZ2xvYmFsT3B0aW9ucy5icmVhZGNydW1iQ2FsbGJhY2spKSB7XG4gICAgICB2YXIgcmVzdWx0ID0gdGhpcy5fZ2xvYmFsT3B0aW9ucy5icmVhZGNydW1iQ2FsbGJhY2soY3J1bWIpO1xuXG4gICAgICBpZiAoaXNPYmplY3QocmVzdWx0KSAmJiAhaXNFbXB0eU9iamVjdChyZXN1bHQpKSB7XG4gICAgICAgIGNydW1iID0gcmVzdWx0O1xuICAgICAgfSBlbHNlIGlmIChyZXN1bHQgPT09IGZhbHNlKSB7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgICAgfVxuICAgIH1cblxuICAgIHRoaXMuX2JyZWFkY3J1bWJzLnB1c2goY3J1bWIpO1xuICAgIGlmICh0aGlzLl9icmVhZGNydW1icy5sZW5ndGggPiB0aGlzLl9nbG9iYWxPcHRpb25zLm1heEJyZWFkY3J1bWJzKSB7XG4gICAgICB0aGlzLl9icmVhZGNydW1icy5zaGlmdCgpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcztcbiAgfSxcblxuICBhZGRQbHVnaW46IGZ1bmN0aW9uKHBsdWdpbiAvKmFyZzEsIGFyZzIsIC4uLiBhcmdOKi8pIHtcbiAgICB2YXIgcGx1Z2luQXJncyA9IFtdLnNsaWNlLmNhbGwoYXJndW1lbnRzLCAxKTtcblxuICAgIHRoaXMuX3BsdWdpbnMucHVzaChbcGx1Z2luLCBwbHVnaW5BcmdzXSk7XG4gICAgaWYgKHRoaXMuX2lzUmF2ZW5JbnN0YWxsZWQpIHtcbiAgICAgIHRoaXMuX2RyYWluUGx1Z2lucygpO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIC8qXG4gICAgICogU2V0L2NsZWFyIGEgdXNlciB0byBiZSBzZW50IGFsb25nIHdpdGggdGhlIHBheWxvYWQuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge29iamVjdH0gdXNlciBBbiBvYmplY3QgcmVwcmVzZW50aW5nIHVzZXIgZGF0YSBbb3B0aW9uYWxdXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIHNldFVzZXJDb250ZXh0OiBmdW5jdGlvbih1c2VyKSB7XG4gICAgLy8gSW50ZW50aW9uYWxseSBkbyBub3QgbWVyZ2UgaGVyZSBzaW5jZSB0aGF0J3MgYW4gdW5leHBlY3RlZCBiZWhhdmlvci5cbiAgICB0aGlzLl9nbG9iYWxDb250ZXh0LnVzZXIgPSB1c2VyO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBNZXJnZSBleHRyYSBhdHRyaWJ1dGVzIHRvIGJlIHNlbnQgYWxvbmcgd2l0aCB0aGUgcGF5bG9hZC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7b2JqZWN0fSBleHRyYSBBbiBvYmplY3QgcmVwcmVzZW50aW5nIGV4dHJhIGRhdGEgW29wdGlvbmFsXVxuICAgICAqIEByZXR1cm4ge1JhdmVufVxuICAgICAqL1xuICBzZXRFeHRyYUNvbnRleHQ6IGZ1bmN0aW9uKGV4dHJhKSB7XG4gICAgdGhpcy5fbWVyZ2VDb250ZXh0KCdleHRyYScsIGV4dHJhKTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIC8qXG4gICAgICogTWVyZ2UgdGFncyB0byBiZSBzZW50IGFsb25nIHdpdGggdGhlIHBheWxvYWQuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge29iamVjdH0gdGFncyBBbiBvYmplY3QgcmVwcmVzZW50aW5nIHRhZ3MgW29wdGlvbmFsXVxuICAgICAqIEByZXR1cm4ge1JhdmVufVxuICAgICAqL1xuICBzZXRUYWdzQ29udGV4dDogZnVuY3Rpb24odGFncykge1xuICAgIHRoaXMuX21lcmdlQ29udGV4dCgndGFncycsIHRhZ3MpO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBDbGVhciBhbGwgb2YgdGhlIGNvbnRleHQuXG4gICAgICpcbiAgICAgKiBAcmV0dXJuIHtSYXZlbn1cbiAgICAgKi9cbiAgY2xlYXJDb250ZXh0OiBmdW5jdGlvbigpIHtcbiAgICB0aGlzLl9nbG9iYWxDb250ZXh0ID0ge307XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfSxcblxuICAvKlxuICAgICAqIEdldCBhIGNvcHkgb2YgdGhlIGN1cnJlbnQgY29udGV4dC4gVGhpcyBjYW5ub3QgYmUgbXV0YXRlZC5cbiAgICAgKlxuICAgICAqIEByZXR1cm4ge29iamVjdH0gY29weSBvZiBjb250ZXh0XG4gICAgICovXG4gIGdldENvbnRleHQ6IGZ1bmN0aW9uKCkge1xuICAgIC8vIGxvbCBqYXZhc2NyaXB0XG4gICAgcmV0dXJuIEpTT04ucGFyc2Uoc3RyaW5naWZ5KHRoaXMuX2dsb2JhbENvbnRleHQpKTtcbiAgfSxcblxuICAvKlxuICAgICAqIFNldCBlbnZpcm9ubWVudCBvZiBhcHBsaWNhdGlvblxuICAgICAqXG4gICAgICogQHBhcmFtIHtzdHJpbmd9IGVudmlyb25tZW50IFR5cGljYWxseSBzb21ldGhpbmcgbGlrZSAncHJvZHVjdGlvbicuXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIHNldEVudmlyb25tZW50OiBmdW5jdGlvbihlbnZpcm9ubWVudCkge1xuICAgIHRoaXMuX2dsb2JhbE9wdGlvbnMuZW52aXJvbm1lbnQgPSBlbnZpcm9ubWVudDtcblxuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIC8qXG4gICAgICogU2V0IHJlbGVhc2UgdmVyc2lvbiBvZiBhcHBsaWNhdGlvblxuICAgICAqXG4gICAgICogQHBhcmFtIHtzdHJpbmd9IHJlbGVhc2UgVHlwaWNhbGx5IHNvbWV0aGluZyBsaWtlIGEgZ2l0IFNIQSB0byBpZGVudGlmeSB2ZXJzaW9uXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIHNldFJlbGVhc2U6IGZ1bmN0aW9uKHJlbGVhc2UpIHtcbiAgICB0aGlzLl9nbG9iYWxPcHRpb25zLnJlbGVhc2UgPSByZWxlYXNlO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBTZXQgdGhlIGRhdGFDYWxsYmFjayBvcHRpb25cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7ZnVuY3Rpb259IGNhbGxiYWNrIFRoZSBjYWxsYmFjayB0byBydW4gd2hpY2ggYWxsb3dzIHRoZVxuICAgICAqICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRhdGEgYmxvYiB0byBiZSBtdXRhdGVkIGJlZm9yZSBzZW5kaW5nXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIHNldERhdGFDYWxsYmFjazogZnVuY3Rpb24oY2FsbGJhY2spIHtcbiAgICB2YXIgb3JpZ2luYWwgPSB0aGlzLl9nbG9iYWxPcHRpb25zLmRhdGFDYWxsYmFjaztcbiAgICB0aGlzLl9nbG9iYWxPcHRpb25zLmRhdGFDYWxsYmFjayA9IGtlZXBPcmlnaW5hbENhbGxiYWNrKG9yaWdpbmFsLCBjYWxsYmFjayk7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBTZXQgdGhlIGJyZWFkY3J1bWJDYWxsYmFjayBvcHRpb25cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7ZnVuY3Rpb259IGNhbGxiYWNrIFRoZSBjYWxsYmFjayB0byBydW4gd2hpY2ggYWxsb3dzIGZpbHRlcmluZ1xuICAgICAqICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9yIG11dGF0aW5nIGJyZWFkY3J1bWJzXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIHNldEJyZWFkY3J1bWJDYWxsYmFjazogZnVuY3Rpb24oY2FsbGJhY2spIHtcbiAgICB2YXIgb3JpZ2luYWwgPSB0aGlzLl9nbG9iYWxPcHRpb25zLmJyZWFkY3J1bWJDYWxsYmFjaztcbiAgICB0aGlzLl9nbG9iYWxPcHRpb25zLmJyZWFkY3J1bWJDYWxsYmFjayA9IGtlZXBPcmlnaW5hbENhbGxiYWNrKG9yaWdpbmFsLCBjYWxsYmFjayk7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBTZXQgdGhlIHNob3VsZFNlbmRDYWxsYmFjayBvcHRpb25cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7ZnVuY3Rpb259IGNhbGxiYWNrIFRoZSBjYWxsYmFjayB0byBydW4gd2hpY2ggYWxsb3dzXG4gICAgICogICAgICAgICAgICAgICAgICAgICAgICAgICAgaW50cm9zcGVjdGluZyB0aGUgYmxvYiBiZWZvcmUgc2VuZGluZ1xuICAgICAqIEByZXR1cm4ge1JhdmVufVxuICAgICAqL1xuICBzZXRTaG91bGRTZW5kQ2FsbGJhY2s6IGZ1bmN0aW9uKGNhbGxiYWNrKSB7XG4gICAgdmFyIG9yaWdpbmFsID0gdGhpcy5fZ2xvYmFsT3B0aW9ucy5zaG91bGRTZW5kQ2FsbGJhY2s7XG4gICAgdGhpcy5fZ2xvYmFsT3B0aW9ucy5zaG91bGRTZW5kQ2FsbGJhY2sgPSBrZWVwT3JpZ2luYWxDYWxsYmFjayhvcmlnaW5hbCwgY2FsbGJhY2spO1xuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIC8qKlxuICAgICAqIE92ZXJyaWRlIHRoZSBkZWZhdWx0IEhUVFAgdHJhbnNwb3J0IG1lY2hhbmlzbSB0aGF0IHRyYW5zbWl0cyBkYXRhXG4gICAgICogdG8gdGhlIFNlbnRyeSBzZXJ2ZXIuXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge2Z1bmN0aW9ufSB0cmFuc3BvcnQgRnVuY3Rpb24gaW52b2tlZCBpbnN0ZWFkIG9mIHRoZSBkZWZhdWx0XG4gICAgICogICAgICAgICAgICAgICAgICAgICAgICAgICAgIGBtYWtlUmVxdWVzdGAgaGFuZGxlci5cbiAgICAgKlxuICAgICAqIEByZXR1cm4ge1JhdmVufVxuICAgICAqL1xuICBzZXRUcmFuc3BvcnQ6IGZ1bmN0aW9uKHRyYW5zcG9ydCkge1xuICAgIHRoaXMuX2dsb2JhbE9wdGlvbnMudHJhbnNwb3J0ID0gdHJhbnNwb3J0O1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBHZXQgdGhlIGxhdGVzdCByYXcgZXhjZXB0aW9uIHRoYXQgd2FzIGNhcHR1cmVkIGJ5IFJhdmVuLlxuICAgICAqXG4gICAgICogQHJldHVybiB7ZXJyb3J9XG4gICAgICovXG4gIGxhc3RFeGNlcHRpb246IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLl9sYXN0Q2FwdHVyZWRFeGNlcHRpb247XG4gIH0sXG5cbiAgLypcbiAgICAgKiBHZXQgdGhlIGxhc3QgZXZlbnQgaWRcbiAgICAgKlxuICAgICAqIEByZXR1cm4ge3N0cmluZ31cbiAgICAgKi9cbiAgbGFzdEV2ZW50SWQ6IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLl9sYXN0RXZlbnRJZDtcbiAgfSxcblxuICAvKlxuICAgICAqIERldGVybWluZSBpZiBSYXZlbiBpcyBzZXR1cCBhbmQgcmVhZHkgdG8gZ28uXG4gICAgICpcbiAgICAgKiBAcmV0dXJuIHtib29sZWFufVxuICAgICAqL1xuICBpc1NldHVwOiBmdW5jdGlvbigpIHtcbiAgICBpZiAoIXRoaXMuX2hhc0pTT04pIHJldHVybiBmYWxzZTsgLy8gbmVlZHMgSlNPTiBzdXBwb3J0XG4gICAgaWYgKCF0aGlzLl9nbG9iYWxTZXJ2ZXIpIHtcbiAgICAgIGlmICghdGhpcy5yYXZlbk5vdENvbmZpZ3VyZWRFcnJvcikge1xuICAgICAgICB0aGlzLnJhdmVuTm90Q29uZmlndXJlZEVycm9yID0gdHJ1ZTtcbiAgICAgICAgdGhpcy5fbG9nRGVidWcoJ2Vycm9yJywgJ0Vycm9yOiBSYXZlbiBoYXMgbm90IGJlZW4gY29uZmlndXJlZC4nKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgcmV0dXJuIHRydWU7XG4gIH0sXG5cbiAgYWZ0ZXJMb2FkOiBmdW5jdGlvbigpIHtcbiAgICAvLyBUT0RPOiByZW1vdmUgd2luZG93IGRlcGVuZGVuY2U/XG5cbiAgICAvLyBBdHRlbXB0IHRvIGluaXRpYWxpemUgUmF2ZW4gb24gbG9hZFxuICAgIHZhciBSYXZlbkNvbmZpZyA9IF93aW5kb3cuUmF2ZW5Db25maWc7XG4gICAgaWYgKFJhdmVuQ29uZmlnKSB7XG4gICAgICB0aGlzLmNvbmZpZyhSYXZlbkNvbmZpZy5kc24sIFJhdmVuQ29uZmlnLmNvbmZpZykuaW5zdGFsbCgpO1xuICAgIH1cbiAgfSxcblxuICBzaG93UmVwb3J0RGlhbG9nOiBmdW5jdGlvbihvcHRpb25zKSB7XG4gICAgaWYgKFxuICAgICAgIV9kb2N1bWVudCAvLyBkb2Vzbid0IHdvcmsgd2l0aG91dCBhIGRvY3VtZW50IChSZWFjdCBuYXRpdmUpXG4gICAgKVxuICAgICAgcmV0dXJuO1xuXG4gICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG5cbiAgICB2YXIgbGFzdEV2ZW50SWQgPSBvcHRpb25zLmV2ZW50SWQgfHwgdGhpcy5sYXN0RXZlbnRJZCgpO1xuICAgIGlmICghbGFzdEV2ZW50SWQpIHtcbiAgICAgIHRocm93IG5ldyBSYXZlbkNvbmZpZ0Vycm9yKCdNaXNzaW5nIGV2ZW50SWQnKTtcbiAgICB9XG5cbiAgICB2YXIgZHNuID0gb3B0aW9ucy5kc24gfHwgdGhpcy5fZHNuO1xuICAgIGlmICghZHNuKSB7XG4gICAgICB0aHJvdyBuZXcgUmF2ZW5Db25maWdFcnJvcignTWlzc2luZyBEU04nKTtcbiAgICB9XG5cbiAgICB2YXIgZW5jb2RlID0gZW5jb2RlVVJJQ29tcG9uZW50O1xuICAgIHZhciBxcyA9ICcnO1xuICAgIHFzICs9ICc/ZXZlbnRJZD0nICsgZW5jb2RlKGxhc3RFdmVudElkKTtcbiAgICBxcyArPSAnJmRzbj0nICsgZW5jb2RlKGRzbik7XG5cbiAgICB2YXIgdXNlciA9IG9wdGlvbnMudXNlciB8fCB0aGlzLl9nbG9iYWxDb250ZXh0LnVzZXI7XG4gICAgaWYgKHVzZXIpIHtcbiAgICAgIGlmICh1c2VyLm5hbWUpIHFzICs9ICcmbmFtZT0nICsgZW5jb2RlKHVzZXIubmFtZSk7XG4gICAgICBpZiAodXNlci5lbWFpbCkgcXMgKz0gJyZlbWFpbD0nICsgZW5jb2RlKHVzZXIuZW1haWwpO1xuICAgIH1cblxuICAgIHZhciBnbG9iYWxTZXJ2ZXIgPSB0aGlzLl9nZXRHbG9iYWxTZXJ2ZXIodGhpcy5fcGFyc2VEU04oZHNuKSk7XG5cbiAgICB2YXIgc2NyaXB0ID0gX2RvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NjcmlwdCcpO1xuICAgIHNjcmlwdC5hc3luYyA9IHRydWU7XG4gICAgc2NyaXB0LnNyYyA9IGdsb2JhbFNlcnZlciArICcvYXBpL2VtYmVkL2Vycm9yLXBhZ2UvJyArIHFzO1xuICAgIChfZG9jdW1lbnQuaGVhZCB8fCBfZG9jdW1lbnQuYm9keSkuYXBwZW5kQ2hpbGQoc2NyaXB0KTtcbiAgfSxcblxuICAvKioqKiBQcml2YXRlIGZ1bmN0aW9ucyAqKioqL1xuICBfaWdub3JlTmV4dE9uRXJyb3I6IGZ1bmN0aW9uKCkge1xuICAgIHZhciBzZWxmID0gdGhpcztcbiAgICB0aGlzLl9pZ25vcmVPbkVycm9yICs9IDE7XG4gICAgc2V0VGltZW91dChmdW5jdGlvbigpIHtcbiAgICAgIC8vIG9uZXJyb3Igc2hvdWxkIHRyaWdnZXIgYmVmb3JlIHNldFRpbWVvdXRcbiAgICAgIHNlbGYuX2lnbm9yZU9uRXJyb3IgLT0gMTtcbiAgICB9KTtcbiAgfSxcblxuICBfdHJpZ2dlckV2ZW50OiBmdW5jdGlvbihldmVudFR5cGUsIG9wdGlvbnMpIHtcbiAgICAvLyBOT1RFOiBgZXZlbnRgIGlzIGEgbmF0aXZlIGJyb3dzZXIgdGhpbmcsIHNvIGxldCdzIGF2b2lkIGNvbmZsaWN0aW5nIHdpaHQgaXRcbiAgICB2YXIgZXZ0LCBrZXk7XG5cbiAgICBpZiAoIXRoaXMuX2hhc0RvY3VtZW50KSByZXR1cm47XG5cbiAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcblxuICAgIGV2ZW50VHlwZSA9ICdyYXZlbicgKyBldmVudFR5cGUuc3Vic3RyKDAsIDEpLnRvVXBwZXJDYXNlKCkgKyBldmVudFR5cGUuc3Vic3RyKDEpO1xuXG4gICAgaWYgKF9kb2N1bWVudC5jcmVhdGVFdmVudCkge1xuICAgICAgZXZ0ID0gX2RvY3VtZW50LmNyZWF0ZUV2ZW50KCdIVE1MRXZlbnRzJyk7XG4gICAgICBldnQuaW5pdEV2ZW50KGV2ZW50VHlwZSwgdHJ1ZSwgdHJ1ZSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGV2dCA9IF9kb2N1bWVudC5jcmVhdGVFdmVudE9iamVjdCgpO1xuICAgICAgZXZ0LmV2ZW50VHlwZSA9IGV2ZW50VHlwZTtcbiAgICB9XG5cbiAgICBmb3IgKGtleSBpbiBvcHRpb25zKVxuICAgICAgaWYgKGhhc0tleShvcHRpb25zLCBrZXkpKSB7XG4gICAgICAgIGV2dFtrZXldID0gb3B0aW9uc1trZXldO1xuICAgICAgfVxuXG4gICAgaWYgKF9kb2N1bWVudC5jcmVhdGVFdmVudCkge1xuICAgICAgLy8gSUU5IGlmIHN0YW5kYXJkc1xuICAgICAgX2RvY3VtZW50LmRpc3BhdGNoRXZlbnQoZXZ0KTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gSUU4IHJlZ2FyZGxlc3Mgb2YgUXVpcmtzIG9yIFN0YW5kYXJkc1xuICAgICAgLy8gSUU5IGlmIHF1aXJrc1xuICAgICAgdHJ5IHtcbiAgICAgICAgX2RvY3VtZW50LmZpcmVFdmVudCgnb24nICsgZXZ0LmV2ZW50VHlwZS50b0xvd2VyQ2FzZSgpLCBldnQpO1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAvLyBEbyBub3RoaW5nXG4gICAgICB9XG4gICAgfVxuICB9LFxuXG4gIC8qKlxuICAgICAqIFdyYXBzIGFkZEV2ZW50TGlzdGVuZXIgdG8gY2FwdHVyZSBVSSBicmVhZGNydW1ic1xuICAgICAqIEBwYXJhbSBldnROYW1lIHRoZSBldmVudCBuYW1lIChlLmcuIFwiY2xpY2tcIilcbiAgICAgKiBAcmV0dXJucyB7RnVuY3Rpb259XG4gICAgICogQHByaXZhdGVcbiAgICAgKi9cbiAgX2JyZWFkY3J1bWJFdmVudEhhbmRsZXI6IGZ1bmN0aW9uKGV2dE5hbWUpIHtcbiAgICB2YXIgc2VsZiA9IHRoaXM7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKGV2dCkge1xuICAgICAgLy8gcmVzZXQga2V5cHJlc3MgdGltZW91dDsgZS5nLiB0cmlnZ2VyaW5nIGEgJ2NsaWNrJyBhZnRlclxuICAgICAgLy8gYSAna2V5cHJlc3MnIHdpbGwgcmVzZXQgdGhlIGtleXByZXNzIGRlYm91bmNlIHNvIHRoYXQgYSBuZXdcbiAgICAgIC8vIHNldCBvZiBrZXlwcmVzc2VzIGNhbiBiZSByZWNvcmRlZFxuICAgICAgc2VsZi5fa2V5cHJlc3NUaW1lb3V0ID0gbnVsbDtcblxuICAgICAgLy8gSXQncyBwb3NzaWJsZSB0aGlzIGhhbmRsZXIgbWlnaHQgdHJpZ2dlciBtdWx0aXBsZSB0aW1lcyBmb3IgdGhlIHNhbWVcbiAgICAgIC8vIGV2ZW50IChlLmcuIGV2ZW50IHByb3BhZ2F0aW9uIHRocm91Z2ggbm9kZSBhbmNlc3RvcnMpLiBJZ25vcmUgaWYgd2UndmVcbiAgICAgIC8vIGFscmVhZHkgY2FwdHVyZWQgdGhlIGV2ZW50LlxuICAgICAgaWYgKHNlbGYuX2xhc3RDYXB0dXJlZEV2ZW50ID09PSBldnQpIHJldHVybjtcblxuICAgICAgc2VsZi5fbGFzdENhcHR1cmVkRXZlbnQgPSBldnQ7XG5cbiAgICAgIC8vIHRyeS9jYXRjaCBib3RoOlxuICAgICAgLy8gLSBhY2Nlc3NpbmcgZXZ0LnRhcmdldCAoc2VlIGdldHNlbnRyeS9yYXZlbi1qcyM4MzgsICM3NjgpXG4gICAgICAvLyAtIGBodG1sVHJlZUFzU3RyaW5nYCBiZWNhdXNlIGl0J3MgY29tcGxleCwgYW5kIGp1c3QgYWNjZXNzaW5nIHRoZSBET00gaW5jb3JyZWN0bHlcbiAgICAgIC8vICAgY2FuIHRocm93IGFuIGV4Y2VwdGlvbiBpbiBzb21lIGNpcmN1bXN0YW5jZXMuXG4gICAgICB2YXIgdGFyZ2V0O1xuICAgICAgdHJ5IHtcbiAgICAgICAgdGFyZ2V0ID0gaHRtbFRyZWVBc1N0cmluZyhldnQudGFyZ2V0KTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgdGFyZ2V0ID0gJzx1bmtub3duPic7XG4gICAgICB9XG5cbiAgICAgIHNlbGYuY2FwdHVyZUJyZWFkY3J1bWIoe1xuICAgICAgICBjYXRlZ29yeTogJ3VpLicgKyBldnROYW1lLCAvLyBlLmcuIHVpLmNsaWNrLCB1aS5pbnB1dFxuICAgICAgICBtZXNzYWdlOiB0YXJnZXRcbiAgICAgIH0pO1xuICAgIH07XG4gIH0sXG5cbiAgLyoqXG4gICAgICogV3JhcHMgYWRkRXZlbnRMaXN0ZW5lciB0byBjYXB0dXJlIGtleXByZXNzIFVJIGV2ZW50c1xuICAgICAqIEByZXR1cm5zIHtGdW5jdGlvbn1cbiAgICAgKiBAcHJpdmF0ZVxuICAgICAqL1xuICBfa2V5cHJlc3NFdmVudEhhbmRsZXI6IGZ1bmN0aW9uKCkge1xuICAgIHZhciBzZWxmID0gdGhpcyxcbiAgICAgIGRlYm91bmNlRHVyYXRpb24gPSAxMDAwOyAvLyBtaWxsaXNlY29uZHNcblxuICAgIC8vIFRPRE86IGlmIHNvbWVob3cgdXNlciBzd2l0Y2hlcyBrZXlwcmVzcyB0YXJnZXQgYmVmb3JlXG4gICAgLy8gICAgICAgZGVib3VuY2UgdGltZW91dCBpcyB0cmlnZ2VyZWQsIHdlIHdpbGwgb25seSBjYXB0dXJlXG4gICAgLy8gICAgICAgYSBzaW5nbGUgYnJlYWRjcnVtYiBmcm9tIHRoZSBGSVJTVCB0YXJnZXQgKGFjY2VwdGFibGU/KVxuICAgIHJldHVybiBmdW5jdGlvbihldnQpIHtcbiAgICAgIHZhciB0YXJnZXQ7XG4gICAgICB0cnkge1xuICAgICAgICB0YXJnZXQgPSBldnQudGFyZ2V0O1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAvLyBqdXN0IGFjY2Vzc2luZyBldmVudCBwcm9wZXJ0aWVzIGNhbiB0aHJvdyBhbiBleGNlcHRpb24gaW4gc29tZSByYXJlIGNpcmN1bXN0YW5jZXNcbiAgICAgICAgLy8gc2VlOiBodHRwczovL2dpdGh1Yi5jb20vZ2V0c2VudHJ5L3JhdmVuLWpzL2lzc3Vlcy84MzhcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgdmFyIHRhZ05hbWUgPSB0YXJnZXQgJiYgdGFyZ2V0LnRhZ05hbWU7XG5cbiAgICAgIC8vIG9ubHkgY29uc2lkZXIga2V5cHJlc3MgZXZlbnRzIG9uIGFjdHVhbCBpbnB1dCBlbGVtZW50c1xuICAgICAgLy8gdGhpcyB3aWxsIGRpc3JlZ2FyZCBrZXlwcmVzc2VzIHRhcmdldGluZyBib2R5IChlLmcuIHRhYmJpbmdcbiAgICAgIC8vIHRocm91Z2ggZWxlbWVudHMsIGhvdGtleXMsIGV0YylcbiAgICAgIGlmIChcbiAgICAgICAgIXRhZ05hbWUgfHxcbiAgICAgICAgKHRhZ05hbWUgIT09ICdJTlBVVCcgJiYgdGFnTmFtZSAhPT0gJ1RFWFRBUkVBJyAmJiAhdGFyZ2V0LmlzQ29udGVudEVkaXRhYmxlKVxuICAgICAgKVxuICAgICAgICByZXR1cm47XG5cbiAgICAgIC8vIHJlY29yZCBmaXJzdCBrZXlwcmVzcyBpbiBhIHNlcmllcywgYnV0IGlnbm9yZSBzdWJzZXF1ZW50XG4gICAgICAvLyBrZXlwcmVzc2VzIHVudGlsIGRlYm91bmNlIGNsZWFyc1xuICAgICAgdmFyIHRpbWVvdXQgPSBzZWxmLl9rZXlwcmVzc1RpbWVvdXQ7XG4gICAgICBpZiAoIXRpbWVvdXQpIHtcbiAgICAgICAgc2VsZi5fYnJlYWRjcnVtYkV2ZW50SGFuZGxlcignaW5wdXQnKShldnQpO1xuICAgICAgfVxuICAgICAgY2xlYXJUaW1lb3V0KHRpbWVvdXQpO1xuICAgICAgc2VsZi5fa2V5cHJlc3NUaW1lb3V0ID0gc2V0VGltZW91dChmdW5jdGlvbigpIHtcbiAgICAgICAgc2VsZi5fa2V5cHJlc3NUaW1lb3V0ID0gbnVsbDtcbiAgICAgIH0sIGRlYm91bmNlRHVyYXRpb24pO1xuICAgIH07XG4gIH0sXG5cbiAgLyoqXG4gICAgICogQ2FwdHVyZXMgYSBicmVhZGNydW1iIG9mIHR5cGUgXCJuYXZpZ2F0aW9uXCIsIG5vcm1hbGl6aW5nIGlucHV0IFVSTHNcbiAgICAgKiBAcGFyYW0gdG8gdGhlIG9yaWdpbmF0aW5nIFVSTFxuICAgICAqIEBwYXJhbSBmcm9tIHRoZSB0YXJnZXQgVVJMXG4gICAgICogQHByaXZhdGVcbiAgICAgKi9cbiAgX2NhcHR1cmVVcmxDaGFuZ2U6IGZ1bmN0aW9uKGZyb20sIHRvKSB7XG4gICAgdmFyIHBhcnNlZExvYyA9IHBhcnNlVXJsKHRoaXMuX2xvY2F0aW9uLmhyZWYpO1xuICAgIHZhciBwYXJzZWRUbyA9IHBhcnNlVXJsKHRvKTtcbiAgICB2YXIgcGFyc2VkRnJvbSA9IHBhcnNlVXJsKGZyb20pO1xuXG4gICAgLy8gYmVjYXVzZSBvbnBvcHN0YXRlIG9ubHkgdGVsbHMgeW91IHRoZSBcIm5ld1wiICh0bykgdmFsdWUgb2YgbG9jYXRpb24uaHJlZiwgYW5kXG4gICAgLy8gbm90IHRoZSBwcmV2aW91cyAoZnJvbSkgdmFsdWUsIHdlIG5lZWQgdG8gdHJhY2sgdGhlIHZhbHVlIG9mIHRoZSBjdXJyZW50IFVSTFxuICAgIC8vIHN0YXRlIG91cnNlbHZlc1xuICAgIHRoaXMuX2xhc3RIcmVmID0gdG87XG5cbiAgICAvLyBVc2Ugb25seSB0aGUgcGF0aCBjb21wb25lbnQgb2YgdGhlIFVSTCBpZiB0aGUgVVJMIG1hdGNoZXMgdGhlIGN1cnJlbnRcbiAgICAvLyBkb2N1bWVudCAoYWxtb3N0IGFsbCB0aGUgdGltZSB3aGVuIHVzaW5nIHB1c2hTdGF0ZSlcbiAgICBpZiAocGFyc2VkTG9jLnByb3RvY29sID09PSBwYXJzZWRUby5wcm90b2NvbCAmJiBwYXJzZWRMb2MuaG9zdCA9PT0gcGFyc2VkVG8uaG9zdClcbiAgICAgIHRvID0gcGFyc2VkVG8ucmVsYXRpdmU7XG4gICAgaWYgKHBhcnNlZExvYy5wcm90b2NvbCA9PT0gcGFyc2VkRnJvbS5wcm90b2NvbCAmJiBwYXJzZWRMb2MuaG9zdCA9PT0gcGFyc2VkRnJvbS5ob3N0KVxuICAgICAgZnJvbSA9IHBhcnNlZEZyb20ucmVsYXRpdmU7XG5cbiAgICB0aGlzLmNhcHR1cmVCcmVhZGNydW1iKHtcbiAgICAgIGNhdGVnb3J5OiAnbmF2aWdhdGlvbicsXG4gICAgICBkYXRhOiB7XG4gICAgICAgIHRvOiB0byxcbiAgICAgICAgZnJvbTogZnJvbVxuICAgICAgfVxuICAgIH0pO1xuICB9LFxuXG4gIF9wYXRjaEZ1bmN0aW9uVG9TdHJpbmc6IGZ1bmN0aW9uKCkge1xuICAgIHZhciBzZWxmID0gdGhpcztcbiAgICBzZWxmLl9vcmlnaW5hbEZ1bmN0aW9uVG9TdHJpbmcgPSBGdW5jdGlvbi5wcm90b3R5cGUudG9TdHJpbmc7XG4gICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLWV4dGVuZC1uYXRpdmVcbiAgICBGdW5jdGlvbi5wcm90b3R5cGUudG9TdHJpbmcgPSBmdW5jdGlvbigpIHtcbiAgICAgIGlmICh0eXBlb2YgdGhpcyA9PT0gJ2Z1bmN0aW9uJyAmJiB0aGlzLl9fcmF2ZW5fXykge1xuICAgICAgICByZXR1cm4gc2VsZi5fb3JpZ2luYWxGdW5jdGlvblRvU3RyaW5nLmFwcGx5KHRoaXMuX19vcmlnX18sIGFyZ3VtZW50cyk7XG4gICAgICB9XG4gICAgICByZXR1cm4gc2VsZi5fb3JpZ2luYWxGdW5jdGlvblRvU3RyaW5nLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG4gICAgfTtcbiAgfSxcblxuICBfdW5wYXRjaEZ1bmN0aW9uVG9TdHJpbmc6IGZ1bmN0aW9uKCkge1xuICAgIGlmICh0aGlzLl9vcmlnaW5hbEZ1bmN0aW9uVG9TdHJpbmcpIHtcbiAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby1leHRlbmQtbmF0aXZlXG4gICAgICBGdW5jdGlvbi5wcm90b3R5cGUudG9TdHJpbmcgPSB0aGlzLl9vcmlnaW5hbEZ1bmN0aW9uVG9TdHJpbmc7XG4gICAgfVxuICB9LFxuXG4gIC8qKlxuICAgICAqIFdyYXAgdGltZXIgZnVuY3Rpb25zIGFuZCBldmVudCB0YXJnZXRzIHRvIGNhdGNoIGVycm9ycyBhbmQgcHJvdmlkZVxuICAgICAqIGJldHRlciBtZXRhZGF0YS5cbiAgICAgKi9cbiAgX2luc3RydW1lbnRUcnlDYXRjaDogZnVuY3Rpb24oKSB7XG4gICAgdmFyIHNlbGYgPSB0aGlzO1xuXG4gICAgdmFyIHdyYXBwZWRCdWlsdElucyA9IHNlbGYuX3dyYXBwZWRCdWlsdElucztcblxuICAgIGZ1bmN0aW9uIHdyYXBUaW1lRm4ob3JpZykge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGZuLCB0KSB7XG4gICAgICAgIC8vIHByZXNlcnZlIGFyaXR5XG4gICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBhcmd1bWVudHMgdG8gcHJldmVudCBkZW9wdGltaXphdGlvblxuICAgICAgICAvLyBodHRwczovL2dpdGh1Yi5jb20vcGV0a2FhbnRvbm92L2JsdWViaXJkL3dpa2kvT3B0aW1pemF0aW9uLWtpbGxlcnMjMzItbGVha2luZy1hcmd1bWVudHNcbiAgICAgICAgdmFyIGFyZ3MgPSBuZXcgQXJyYXkoYXJndW1lbnRzLmxlbmd0aCk7XG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJncy5sZW5ndGg7ICsraSkge1xuICAgICAgICAgIGFyZ3NbaV0gPSBhcmd1bWVudHNbaV07XG4gICAgICAgIH1cbiAgICAgICAgdmFyIG9yaWdpbmFsQ2FsbGJhY2sgPSBhcmdzWzBdO1xuICAgICAgICBpZiAoaXNGdW5jdGlvbihvcmlnaW5hbENhbGxiYWNrKSkge1xuICAgICAgICAgIGFyZ3NbMF0gPSBzZWxmLndyYXAob3JpZ2luYWxDYWxsYmFjayk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBJRSA8IDkgZG9lc24ndCBzdXBwb3J0IC5jYWxsLy5hcHBseSBvbiBzZXRJbnRlcnZhbC9zZXRUaW1lb3V0LCBidXQgaXRcbiAgICAgICAgLy8gYWxzbyBzdXBwb3J0cyBvbmx5IHR3byBhcmd1bWVudHMgYW5kIGRvZXNuJ3QgY2FyZSB3aGF0IHRoaXMgaXMsIHNvIHdlXG4gICAgICAgIC8vIGNhbiBqdXN0IGNhbGwgdGhlIG9yaWdpbmFsIGZ1bmN0aW9uIGRpcmVjdGx5LlxuICAgICAgICBpZiAob3JpZy5hcHBseSkge1xuICAgICAgICAgIHJldHVybiBvcmlnLmFwcGx5KHRoaXMsIGFyZ3MpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHJldHVybiBvcmlnKGFyZ3NbMF0sIGFyZ3NbMV0pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIHZhciBhdXRvQnJlYWRjcnVtYnMgPSB0aGlzLl9nbG9iYWxPcHRpb25zLmF1dG9CcmVhZGNydW1icztcblxuICAgIGZ1bmN0aW9uIHdyYXBFdmVudFRhcmdldChnbG9iYWwpIHtcbiAgICAgIHZhciBwcm90byA9IF93aW5kb3dbZ2xvYmFsXSAmJiBfd2luZG93W2dsb2JhbF0ucHJvdG90eXBlO1xuICAgICAgaWYgKHByb3RvICYmIHByb3RvLmhhc093blByb3BlcnR5ICYmIHByb3RvLmhhc093blByb3BlcnR5KCdhZGRFdmVudExpc3RlbmVyJykpIHtcbiAgICAgICAgZmlsbChcbiAgICAgICAgICBwcm90byxcbiAgICAgICAgICAnYWRkRXZlbnRMaXN0ZW5lcicsXG4gICAgICAgICAgZnVuY3Rpb24ob3JpZykge1xuICAgICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKGV2dE5hbWUsIGZuLCBjYXB0dXJlLCBzZWN1cmUpIHtcbiAgICAgICAgICAgICAgLy8gcHJlc2VydmUgYXJpdHlcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBpZiAoZm4gJiYgZm4uaGFuZGxlRXZlbnQpIHtcbiAgICAgICAgICAgICAgICAgIGZuLmhhbmRsZUV2ZW50ID0gc2VsZi53cmFwKGZuLmhhbmRsZUV2ZW50KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICAgICAgICAgIC8vIGNhbiBzb21ldGltZXMgZ2V0ICdQZXJtaXNzaW9uIGRlbmllZCB0byBhY2Nlc3MgcHJvcGVydHkgXCJoYW5kbGUgRXZlbnQnXG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAvLyBNb3JlIGJyZWFkY3J1bWIgRE9NIGNhcHR1cmUgLi4uIGRvbmUgaGVyZSBhbmQgbm90IGluIGBfaW5zdHJ1bWVudEJyZWFkY3J1bWJzYFxuICAgICAgICAgICAgICAvLyBzbyB0aGF0IHdlIGRvbid0IGhhdmUgbW9yZSB0aGFuIG9uZSB3cmFwcGVyIGZ1bmN0aW9uXG4gICAgICAgICAgICAgIHZhciBiZWZvcmUsIGNsaWNrSGFuZGxlciwga2V5cHJlc3NIYW5kbGVyO1xuXG4gICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICBhdXRvQnJlYWRjcnVtYnMgJiZcbiAgICAgICAgICAgICAgICBhdXRvQnJlYWRjcnVtYnMuZG9tICYmXG4gICAgICAgICAgICAgICAgKGdsb2JhbCA9PT0gJ0V2ZW50VGFyZ2V0JyB8fCBnbG9iYWwgPT09ICdOb2RlJylcbiAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgLy8gTk9URTogZ2VuZXJhdGluZyBtdWx0aXBsZSBoYW5kbGVycyBwZXIgYWRkRXZlbnRMaXN0ZW5lciBpbnZvY2F0aW9uLCBzaG91bGRcbiAgICAgICAgICAgICAgICAvLyAgICAgICByZXZpc2l0IGFuZCB2ZXJpZnkgd2UgY2FuIGp1c3QgdXNlIG9uZSAoYWxtb3N0IGNlcnRhaW5seSlcbiAgICAgICAgICAgICAgICBjbGlja0hhbmRsZXIgPSBzZWxmLl9icmVhZGNydW1iRXZlbnRIYW5kbGVyKCdjbGljaycpO1xuICAgICAgICAgICAgICAgIGtleXByZXNzSGFuZGxlciA9IHNlbGYuX2tleXByZXNzRXZlbnRIYW5kbGVyKCk7XG4gICAgICAgICAgICAgICAgYmVmb3JlID0gZnVuY3Rpb24oZXZ0KSB7XG4gICAgICAgICAgICAgICAgICAvLyBuZWVkIHRvIGludGVyY2VwdCBldmVyeSBET00gZXZlbnQgaW4gYGJlZm9yZWAgYXJndW1lbnQsIGluIGNhc2UgdGhhdFxuICAgICAgICAgICAgICAgICAgLy8gc2FtZSB3cmFwcGVkIG1ldGhvZCBpcyByZS11c2VkIGZvciBkaWZmZXJlbnQgZXZlbnRzIChlLmcuIG1vdXNlbW92ZSBUSEVOIGNsaWNrKVxuICAgICAgICAgICAgICAgICAgLy8gc2VlICM3MjRcbiAgICAgICAgICAgICAgICAgIGlmICghZXZ0KSByZXR1cm47XG5cbiAgICAgICAgICAgICAgICAgIHZhciBldmVudFR5cGU7XG4gICAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgICBldmVudFR5cGUgPSBldnQudHlwZTtcbiAgICAgICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICAgICAgLy8ganVzdCBhY2Nlc3NpbmcgZXZlbnQgcHJvcGVydGllcyBjYW4gdGhyb3cgYW4gZXhjZXB0aW9uIGluIHNvbWUgcmFyZSBjaXJjdW1zdGFuY2VzXG4gICAgICAgICAgICAgICAgICAgIC8vIHNlZTogaHR0cHM6Ly9naXRodWIuY29tL2dldHNlbnRyeS9yYXZlbi1qcy9pc3N1ZXMvODM4XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgIGlmIChldmVudFR5cGUgPT09ICdjbGljaycpIHJldHVybiBjbGlja0hhbmRsZXIoZXZ0KTtcbiAgICAgICAgICAgICAgICAgIGVsc2UgaWYgKGV2ZW50VHlwZSA9PT0gJ2tleXByZXNzJykgcmV0dXJuIGtleXByZXNzSGFuZGxlcihldnQpO1xuICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgcmV0dXJuIG9yaWcuY2FsbChcbiAgICAgICAgICAgICAgICB0aGlzLFxuICAgICAgICAgICAgICAgIGV2dE5hbWUsXG4gICAgICAgICAgICAgICAgc2VsZi53cmFwKGZuLCB1bmRlZmluZWQsIGJlZm9yZSksXG4gICAgICAgICAgICAgICAgY2FwdHVyZSxcbiAgICAgICAgICAgICAgICBzZWN1cmVcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgfSxcbiAgICAgICAgICB3cmFwcGVkQnVpbHRJbnNcbiAgICAgICAgKTtcbiAgICAgICAgZmlsbChcbiAgICAgICAgICBwcm90byxcbiAgICAgICAgICAncmVtb3ZlRXZlbnRMaXN0ZW5lcicsXG4gICAgICAgICAgZnVuY3Rpb24ob3JpZykge1xuICAgICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKGV2dCwgZm4sIGNhcHR1cmUsIHNlY3VyZSkge1xuICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGZuID0gZm4gJiYgKGZuLl9fcmF2ZW5fd3JhcHBlcl9fID8gZm4uX19yYXZlbl93cmFwcGVyX18gOiBmbik7XG4gICAgICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICAvLyBpZ25vcmUsIGFjY2Vzc2luZyBfX3JhdmVuX3dyYXBwZXJfXyB3aWxsIHRocm93IGluIHNvbWUgU2VsZW5pdW0gZW52aXJvbm1lbnRzXG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgcmV0dXJuIG9yaWcuY2FsbCh0aGlzLCBldnQsIGZuLCBjYXB0dXJlLCBzZWN1cmUpO1xuICAgICAgICAgICAgfTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIHdyYXBwZWRCdWlsdEluc1xuICAgICAgICApO1xuICAgICAgfVxuICAgIH1cblxuICAgIGZpbGwoX3dpbmRvdywgJ3NldFRpbWVvdXQnLCB3cmFwVGltZUZuLCB3cmFwcGVkQnVpbHRJbnMpO1xuICAgIGZpbGwoX3dpbmRvdywgJ3NldEludGVydmFsJywgd3JhcFRpbWVGbiwgd3JhcHBlZEJ1aWx0SW5zKTtcbiAgICBpZiAoX3dpbmRvdy5yZXF1ZXN0QW5pbWF0aW9uRnJhbWUpIHtcbiAgICAgIGZpbGwoXG4gICAgICAgIF93aW5kb3csXG4gICAgICAgICdyZXF1ZXN0QW5pbWF0aW9uRnJhbWUnLFxuICAgICAgICBmdW5jdGlvbihvcmlnKSB7XG4gICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKGNiKSB7XG4gICAgICAgICAgICByZXR1cm4gb3JpZyhzZWxmLndyYXAoY2IpKTtcbiAgICAgICAgICB9O1xuICAgICAgICB9LFxuICAgICAgICB3cmFwcGVkQnVpbHRJbnNcbiAgICAgICk7XG4gICAgfVxuXG4gICAgLy8gZXZlbnQgdGFyZ2V0cyBib3Jyb3dlZCBmcm9tIGJ1Z3NuYWctanM6XG4gICAgLy8gaHR0cHM6Ly9naXRodWIuY29tL2J1Z3NuYWcvYnVnc25hZy1qcy9ibG9iL21hc3Rlci9zcmMvYnVnc25hZy5qcyNMNjY2XG4gICAgdmFyIGV2ZW50VGFyZ2V0cyA9IFtcbiAgICAgICdFdmVudFRhcmdldCcsXG4gICAgICAnV2luZG93JyxcbiAgICAgICdOb2RlJyxcbiAgICAgICdBcHBsaWNhdGlvbkNhY2hlJyxcbiAgICAgICdBdWRpb1RyYWNrTGlzdCcsXG4gICAgICAnQ2hhbm5lbE1lcmdlck5vZGUnLFxuICAgICAgJ0NyeXB0b09wZXJhdGlvbicsXG4gICAgICAnRXZlbnRTb3VyY2UnLFxuICAgICAgJ0ZpbGVSZWFkZXInLFxuICAgICAgJ0hUTUxVbmtub3duRWxlbWVudCcsXG4gICAgICAnSURCRGF0YWJhc2UnLFxuICAgICAgJ0lEQlJlcXVlc3QnLFxuICAgICAgJ0lEQlRyYW5zYWN0aW9uJyxcbiAgICAgICdLZXlPcGVyYXRpb24nLFxuICAgICAgJ01lZGlhQ29udHJvbGxlcicsXG4gICAgICAnTWVzc2FnZVBvcnQnLFxuICAgICAgJ01vZGFsV2luZG93JyxcbiAgICAgICdOb3RpZmljYXRpb24nLFxuICAgICAgJ1NWR0VsZW1lbnRJbnN0YW5jZScsXG4gICAgICAnU2NyZWVuJyxcbiAgICAgICdUZXh0VHJhY2snLFxuICAgICAgJ1RleHRUcmFja0N1ZScsXG4gICAgICAnVGV4dFRyYWNrTGlzdCcsXG4gICAgICAnV2ViU29ja2V0JyxcbiAgICAgICdXZWJTb2NrZXRXb3JrZXInLFxuICAgICAgJ1dvcmtlcicsXG4gICAgICAnWE1MSHR0cFJlcXVlc3QnLFxuICAgICAgJ1hNTEh0dHBSZXF1ZXN0RXZlbnRUYXJnZXQnLFxuICAgICAgJ1hNTEh0dHBSZXF1ZXN0VXBsb2FkJ1xuICAgIF07XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBldmVudFRhcmdldHMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHdyYXBFdmVudFRhcmdldChldmVudFRhcmdldHNbaV0pO1xuICAgIH1cbiAgfSxcblxuICAvKipcbiAgICAgKiBJbnN0cnVtZW50IGJyb3dzZXIgYnVpbHQtaW5zIHcvIGJyZWFkY3J1bWIgY2FwdHVyaW5nXG4gICAgICogIC0gWE1MSHR0cFJlcXVlc3RzXG4gICAgICogIC0gRE9NIGludGVyYWN0aW9ucyAoY2xpY2svdHlwaW5nKVxuICAgICAqICAtIHdpbmRvdy5sb2NhdGlvbiBjaGFuZ2VzXG4gICAgICogIC0gY29uc29sZVxuICAgICAqXG4gICAgICogQ2FuIGJlIGRpc2FibGVkIG9yIGluZGl2aWR1YWxseSBjb25maWd1cmVkIHZpYSB0aGUgYGF1dG9CcmVhZGNydW1ic2AgY29uZmlnIG9wdGlvblxuICAgICAqL1xuICBfaW5zdHJ1bWVudEJyZWFkY3J1bWJzOiBmdW5jdGlvbigpIHtcbiAgICB2YXIgc2VsZiA9IHRoaXM7XG4gICAgdmFyIGF1dG9CcmVhZGNydW1icyA9IHRoaXMuX2dsb2JhbE9wdGlvbnMuYXV0b0JyZWFkY3J1bWJzO1xuXG4gICAgdmFyIHdyYXBwZWRCdWlsdElucyA9IHNlbGYuX3dyYXBwZWRCdWlsdElucztcblxuICAgIGZ1bmN0aW9uIHdyYXBQcm9wKHByb3AsIHhocikge1xuICAgICAgaWYgKHByb3AgaW4geGhyICYmIGlzRnVuY3Rpb24oeGhyW3Byb3BdKSkge1xuICAgICAgICBmaWxsKHhociwgcHJvcCwgZnVuY3Rpb24ob3JpZykge1xuICAgICAgICAgIHJldHVybiBzZWxmLndyYXAob3JpZyk7XG4gICAgICAgIH0pOyAvLyBpbnRlbnRpb25hbGx5IGRvbid0IHRyYWNrIGZpbGxlZCBtZXRob2RzIG9uIFhIUiBpbnN0YW5jZXNcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoYXV0b0JyZWFkY3J1bWJzLnhociAmJiAnWE1MSHR0cFJlcXVlc3QnIGluIF93aW5kb3cpIHtcbiAgICAgIHZhciB4aHJwcm90byA9IFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZTtcbiAgICAgIGZpbGwoXG4gICAgICAgIHhocnByb3RvLFxuICAgICAgICAnb3BlbicsXG4gICAgICAgIGZ1bmN0aW9uKG9yaWdPcGVuKSB7XG4gICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKG1ldGhvZCwgdXJsKSB7XG4gICAgICAgICAgICAvLyBwcmVzZXJ2ZSBhcml0eVxuXG4gICAgICAgICAgICAvLyBpZiBTZW50cnkga2V5IGFwcGVhcnMgaW4gVVJMLCBkb24ndCBjYXB0dXJlXG4gICAgICAgICAgICBpZiAoaXNTdHJpbmcodXJsKSAmJiB1cmwuaW5kZXhPZihzZWxmLl9nbG9iYWxLZXkpID09PSAtMSkge1xuICAgICAgICAgICAgICB0aGlzLl9fcmF2ZW5feGhyID0ge1xuICAgICAgICAgICAgICAgIG1ldGhvZDogbWV0aG9kLFxuICAgICAgICAgICAgICAgIHVybDogdXJsLFxuICAgICAgICAgICAgICAgIHN0YXR1c19jb2RlOiBudWxsXG4gICAgICAgICAgICAgIH07XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHJldHVybiBvcmlnT3Blbi5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xuICAgICAgICAgIH07XG4gICAgICAgIH0sXG4gICAgICAgIHdyYXBwZWRCdWlsdEluc1xuICAgICAgKTtcblxuICAgICAgZmlsbChcbiAgICAgICAgeGhycHJvdG8sXG4gICAgICAgICdzZW5kJyxcbiAgICAgICAgZnVuY3Rpb24ob3JpZ1NlbmQpIHtcbiAgICAgICAgICByZXR1cm4gZnVuY3Rpb24oZGF0YSkge1xuICAgICAgICAgICAgLy8gcHJlc2VydmUgYXJpdHlcbiAgICAgICAgICAgIHZhciB4aHIgPSB0aGlzO1xuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbnJlYWR5c3RhdGVjaGFuZ2VIYW5kbGVyKCkge1xuICAgICAgICAgICAgICBpZiAoeGhyLl9fcmF2ZW5feGhyICYmIHhoci5yZWFkeVN0YXRlID09PSA0KSB7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgIC8vIHRvdWNoaW5nIHN0YXR1c0NvZGUgaW4gc29tZSBwbGF0Zm9ybXMgdGhyb3dzXG4gICAgICAgICAgICAgICAgICAvLyBhbiBleGNlcHRpb25cbiAgICAgICAgICAgICAgICAgIHhoci5fX3JhdmVuX3hoci5zdGF0dXNfY29kZSA9IHhoci5zdGF0dXM7XG4gICAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgICAgLyogZG8gbm90aGluZyAqL1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHNlbGYuY2FwdHVyZUJyZWFkY3J1bWIoe1xuICAgICAgICAgICAgICAgICAgdHlwZTogJ2h0dHAnLFxuICAgICAgICAgICAgICAgICAgY2F0ZWdvcnk6ICd4aHInLFxuICAgICAgICAgICAgICAgICAgZGF0YTogeGhyLl9fcmF2ZW5feGhyXG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdmFyIHByb3BzID0gWydvbmxvYWQnLCAnb25lcnJvcicsICdvbnByb2dyZXNzJ107XG4gICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IHByb3BzLmxlbmd0aDsgaisrKSB7XG4gICAgICAgICAgICAgIHdyYXBQcm9wKHByb3BzW2pdLCB4aHIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoJ29ucmVhZHlzdGF0ZWNoYW5nZScgaW4geGhyICYmIGlzRnVuY3Rpb24oeGhyLm9ucmVhZHlzdGF0ZWNoYW5nZSkpIHtcbiAgICAgICAgICAgICAgZmlsbChcbiAgICAgICAgICAgICAgICB4aHIsXG4gICAgICAgICAgICAgICAgJ29ucmVhZHlzdGF0ZWNoYW5nZScsXG4gICAgICAgICAgICAgICAgZnVuY3Rpb24ob3JpZykge1xuICAgICAgICAgICAgICAgICAgcmV0dXJuIHNlbGYud3JhcChvcmlnLCB1bmRlZmluZWQsIG9ucmVhZHlzdGF0ZWNoYW5nZUhhbmRsZXIpO1xuICAgICAgICAgICAgICAgIH0gLyogaW50ZW50aW9uYWxseSBkb24ndCB0cmFjayB0aGlzIGluc3RydW1lbnRhdGlvbiAqL1xuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgLy8gaWYgb25yZWFkeXN0YXRlY2hhbmdlIHdhc24ndCBhY3R1YWxseSBzZXQgYnkgdGhlIHBhZ2Ugb24gdGhpcyB4aHIsIHdlXG4gICAgICAgICAgICAgIC8vIGFyZSBmcmVlIHRvIHNldCBvdXIgb3duIGFuZCBjYXB0dXJlIHRoZSBicmVhZGNydW1iXG4gICAgICAgICAgICAgIHhoci5vbnJlYWR5c3RhdGVjaGFuZ2UgPSBvbnJlYWR5c3RhdGVjaGFuZ2VIYW5kbGVyO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXR1cm4gb3JpZ1NlbmQuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbiAgICAgICAgICB9O1xuICAgICAgICB9LFxuICAgICAgICB3cmFwcGVkQnVpbHRJbnNcbiAgICAgICk7XG4gICAgfVxuXG4gICAgaWYgKGF1dG9CcmVhZGNydW1icy54aHIgJiYgJ2ZldGNoJyBpbiBfd2luZG93KSB7XG4gICAgICBmaWxsKFxuICAgICAgICBfd2luZG93LFxuICAgICAgICAnZmV0Y2gnLFxuICAgICAgICBmdW5jdGlvbihvcmlnRmV0Y2gpIHtcbiAgICAgICAgICByZXR1cm4gZnVuY3Rpb24oZm4sIHQpIHtcbiAgICAgICAgICAgIC8vIHByZXNlcnZlIGFyaXR5XG4gICAgICAgICAgICAvLyBNYWtlIGEgY29weSBvZiB0aGUgYXJndW1lbnRzIHRvIHByZXZlbnQgZGVvcHRpbWl6YXRpb25cbiAgICAgICAgICAgIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9wZXRrYWFudG9ub3YvYmx1ZWJpcmQvd2lraS9PcHRpbWl6YXRpb24ta2lsbGVycyMzMi1sZWFraW5nLWFyZ3VtZW50c1xuICAgICAgICAgICAgdmFyIGFyZ3MgPSBuZXcgQXJyYXkoYXJndW1lbnRzLmxlbmd0aCk7XG4gICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFyZ3MubGVuZ3RoOyArK2kpIHtcbiAgICAgICAgICAgICAgYXJnc1tpXSA9IGFyZ3VtZW50c1tpXTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdmFyIGZldGNoSW5wdXQgPSBhcmdzWzBdO1xuICAgICAgICAgICAgdmFyIG1ldGhvZCA9ICdHRVQnO1xuICAgICAgICAgICAgdmFyIHVybDtcblxuICAgICAgICAgICAgaWYgKHR5cGVvZiBmZXRjaElucHV0ID09PSAnc3RyaW5nJykge1xuICAgICAgICAgICAgICB1cmwgPSBmZXRjaElucHV0O1xuICAgICAgICAgICAgfSBlbHNlIGlmICgnUmVxdWVzdCcgaW4gX3dpbmRvdyAmJiBmZXRjaElucHV0IGluc3RhbmNlb2YgX3dpbmRvdy5SZXF1ZXN0KSB7XG4gICAgICAgICAgICAgIHVybCA9IGZldGNoSW5wdXQudXJsO1xuICAgICAgICAgICAgICBpZiAoZmV0Y2hJbnB1dC5tZXRob2QpIHtcbiAgICAgICAgICAgICAgICBtZXRob2QgPSBmZXRjaElucHV0Lm1ldGhvZDtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgdXJsID0gJycgKyBmZXRjaElucHV0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoYXJnc1sxXSAmJiBhcmdzWzFdLm1ldGhvZCkge1xuICAgICAgICAgICAgICBtZXRob2QgPSBhcmdzWzFdLm1ldGhvZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdmFyIGZldGNoRGF0YSA9IHtcbiAgICAgICAgICAgICAgbWV0aG9kOiBtZXRob2QsXG4gICAgICAgICAgICAgIHVybDogdXJsLFxuICAgICAgICAgICAgICBzdGF0dXNfY29kZTogbnVsbFxuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2VsZi5jYXB0dXJlQnJlYWRjcnVtYih7XG4gICAgICAgICAgICAgIHR5cGU6ICdodHRwJyxcbiAgICAgICAgICAgICAgY2F0ZWdvcnk6ICdmZXRjaCcsXG4gICAgICAgICAgICAgIGRhdGE6IGZldGNoRGF0YVxuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHJldHVybiBvcmlnRmV0Y2guYXBwbHkodGhpcywgYXJncykudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgICAgICBmZXRjaERhdGEuc3RhdHVzX2NvZGUgPSByZXNwb25zZS5zdGF0dXM7XG5cbiAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfTtcbiAgICAgICAgfSxcbiAgICAgICAgd3JhcHBlZEJ1aWx0SW5zXG4gICAgICApO1xuICAgIH1cblxuICAgIC8vIENhcHR1cmUgYnJlYWRjcnVtYnMgZnJvbSBhbnkgY2xpY2sgdGhhdCBpcyB1bmhhbmRsZWQgLyBidWJibGVkIHVwIGFsbCB0aGUgd2F5XG4gICAgLy8gdG8gdGhlIGRvY3VtZW50LiBEbyB0aGlzIGJlZm9yZSB3ZSBpbnN0cnVtZW50IGFkZEV2ZW50TGlzdGVuZXIuXG4gICAgaWYgKGF1dG9CcmVhZGNydW1icy5kb20gJiYgdGhpcy5faGFzRG9jdW1lbnQpIHtcbiAgICAgIGlmIChfZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcikge1xuICAgICAgICBfZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBzZWxmLl9icmVhZGNydW1iRXZlbnRIYW5kbGVyKCdjbGljaycpLCBmYWxzZSk7XG4gICAgICAgIF9kb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdrZXlwcmVzcycsIHNlbGYuX2tleXByZXNzRXZlbnRIYW5kbGVyKCksIGZhbHNlKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vIElFOCBDb21wYXRpYmlsaXR5XG4gICAgICAgIF9kb2N1bWVudC5hdHRhY2hFdmVudCgnb25jbGljaycsIHNlbGYuX2JyZWFkY3J1bWJFdmVudEhhbmRsZXIoJ2NsaWNrJykpO1xuICAgICAgICBfZG9jdW1lbnQuYXR0YWNoRXZlbnQoJ29ua2V5cHJlc3MnLCBzZWxmLl9rZXlwcmVzc0V2ZW50SGFuZGxlcigpKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyByZWNvcmQgbmF2aWdhdGlvbiAoVVJMKSBjaGFuZ2VzXG4gICAgLy8gTk9URTogaW4gQ2hyb21lIEFwcCBlbnZpcm9ubWVudCwgdG91Y2hpbmcgaGlzdG9yeS5wdXNoU3RhdGUsICpldmVuIGluc2lkZVxuICAgIC8vICAgICAgIGEgdHJ5L2NhdGNoIGJsb2NrKiwgd2lsbCBjYXVzZSBDaHJvbWUgdG8gb3V0cHV0IGFuIGVycm9yIHRvIGNvbnNvbGUuZXJyb3JcbiAgICAvLyBib3Jyb3dlZCBmcm9tOiBodHRwczovL2dpdGh1Yi5jb20vYW5ndWxhci9hbmd1bGFyLmpzL3B1bGwvMTM5NDUvZmlsZXNcbiAgICB2YXIgY2hyb21lID0gX3dpbmRvdy5jaHJvbWU7XG4gICAgdmFyIGlzQ2hyb21lUGFja2FnZWRBcHAgPSBjaHJvbWUgJiYgY2hyb21lLmFwcCAmJiBjaHJvbWUuYXBwLnJ1bnRpbWU7XG4gICAgdmFyIGhhc1B1c2hBbmRSZXBsYWNlU3RhdGUgPVxuICAgICAgIWlzQ2hyb21lUGFja2FnZWRBcHAgJiZcbiAgICAgIF93aW5kb3cuaGlzdG9yeSAmJlxuICAgICAgaGlzdG9yeS5wdXNoU3RhdGUgJiZcbiAgICAgIGhpc3RvcnkucmVwbGFjZVN0YXRlO1xuICAgIGlmIChhdXRvQnJlYWRjcnVtYnMubG9jYXRpb24gJiYgaGFzUHVzaEFuZFJlcGxhY2VTdGF0ZSkge1xuICAgICAgLy8gVE9ETzogcmVtb3ZlIG9ucG9wc3RhdGUgaGFuZGxlciBvbiB1bmluc3RhbGwoKVxuICAgICAgdmFyIG9sZE9uUG9wU3RhdGUgPSBfd2luZG93Lm9ucG9wc3RhdGU7XG4gICAgICBfd2luZG93Lm9ucG9wc3RhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGN1cnJlbnRIcmVmID0gc2VsZi5fbG9jYXRpb24uaHJlZjtcbiAgICAgICAgc2VsZi5fY2FwdHVyZVVybENoYW5nZShzZWxmLl9sYXN0SHJlZiwgY3VycmVudEhyZWYpO1xuXG4gICAgICAgIGlmIChvbGRPblBvcFN0YXRlKSB7XG4gICAgICAgICAgcmV0dXJuIG9sZE9uUG9wU3RhdGUuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbiAgICAgICAgfVxuICAgICAgfTtcblxuICAgICAgdmFyIGhpc3RvcnlSZXBsYWNlbWVudEZ1bmN0aW9uID0gZnVuY3Rpb24ob3JpZ0hpc3RGdW5jdGlvbikge1xuICAgICAgICAvLyBub3RlIGhpc3RvcnkucHVzaFN0YXRlLmxlbmd0aCBpcyAwOyBpbnRlbnRpb25hbGx5IG5vdCBkZWNsYXJpbmdcbiAgICAgICAgLy8gcGFyYW1zIHRvIHByZXNlcnZlIDAgYXJpdHlcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKC8qIHN0YXRlLCB0aXRsZSwgdXJsICovKSB7XG4gICAgICAgICAgdmFyIHVybCA9IGFyZ3VtZW50cy5sZW5ndGggPiAyID8gYXJndW1lbnRzWzJdIDogdW5kZWZpbmVkO1xuXG4gICAgICAgICAgLy8gdXJsIGFyZ3VtZW50IGlzIG9wdGlvbmFsXG4gICAgICAgICAgaWYgKHVybCkge1xuICAgICAgICAgICAgLy8gY29lcmNlIHRvIHN0cmluZyAodGhpcyBpcyB3aGF0IHB1c2hTdGF0ZSBkb2VzKVxuICAgICAgICAgICAgc2VsZi5fY2FwdHVyZVVybENoYW5nZShzZWxmLl9sYXN0SHJlZiwgdXJsICsgJycpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBvcmlnSGlzdEZ1bmN0aW9uLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG4gICAgICAgIH07XG4gICAgICB9O1xuXG4gICAgICBmaWxsKGhpc3RvcnksICdwdXNoU3RhdGUnLCBoaXN0b3J5UmVwbGFjZW1lbnRGdW5jdGlvbiwgd3JhcHBlZEJ1aWx0SW5zKTtcbiAgICAgIGZpbGwoaGlzdG9yeSwgJ3JlcGxhY2VTdGF0ZScsIGhpc3RvcnlSZXBsYWNlbWVudEZ1bmN0aW9uLCB3cmFwcGVkQnVpbHRJbnMpO1xuICAgIH1cblxuICAgIGlmIChhdXRvQnJlYWRjcnVtYnMuY29uc29sZSAmJiAnY29uc29sZScgaW4gX3dpbmRvdyAmJiBjb25zb2xlLmxvZykge1xuICAgICAgLy8gY29uc29sZVxuICAgICAgdmFyIGNvbnNvbGVNZXRob2RDYWxsYmFjayA9IGZ1bmN0aW9uKG1zZywgZGF0YSkge1xuICAgICAgICBzZWxmLmNhcHR1cmVCcmVhZGNydW1iKHtcbiAgICAgICAgICBtZXNzYWdlOiBtc2csXG4gICAgICAgICAgbGV2ZWw6IGRhdGEubGV2ZWwsXG4gICAgICAgICAgY2F0ZWdvcnk6ICdjb25zb2xlJ1xuICAgICAgICB9KTtcbiAgICAgIH07XG5cbiAgICAgIGVhY2goWydkZWJ1ZycsICdpbmZvJywgJ3dhcm4nLCAnZXJyb3InLCAnbG9nJ10sIGZ1bmN0aW9uKF8sIGxldmVsKSB7XG4gICAgICAgIHdyYXBDb25zb2xlTWV0aG9kKGNvbnNvbGUsIGxldmVsLCBjb25zb2xlTWV0aG9kQ2FsbGJhY2spO1xuICAgICAgfSk7XG4gICAgfVxuICB9LFxuXG4gIF9yZXN0b3JlQnVpbHRJbnM6IGZ1bmN0aW9uKCkge1xuICAgIC8vIHJlc3RvcmUgYW55IHdyYXBwZWQgYnVpbHRpbnNcbiAgICB2YXIgYnVpbHRpbjtcbiAgICB3aGlsZSAodGhpcy5fd3JhcHBlZEJ1aWx0SW5zLmxlbmd0aCkge1xuICAgICAgYnVpbHRpbiA9IHRoaXMuX3dyYXBwZWRCdWlsdElucy5zaGlmdCgpO1xuXG4gICAgICB2YXIgb2JqID0gYnVpbHRpblswXSxcbiAgICAgICAgbmFtZSA9IGJ1aWx0aW5bMV0sXG4gICAgICAgIG9yaWcgPSBidWlsdGluWzJdO1xuXG4gICAgICBvYmpbbmFtZV0gPSBvcmlnO1xuICAgIH1cbiAgfSxcblxuICBfZHJhaW5QbHVnaW5zOiBmdW5jdGlvbigpIHtcbiAgICB2YXIgc2VsZiA9IHRoaXM7XG5cbiAgICAvLyBGSVggTUUgVE9ET1xuICAgIGVhY2godGhpcy5fcGx1Z2lucywgZnVuY3Rpb24oXywgcGx1Z2luKSB7XG4gICAgICB2YXIgaW5zdGFsbGVyID0gcGx1Z2luWzBdO1xuICAgICAgdmFyIGFyZ3MgPSBwbHVnaW5bMV07XG4gICAgICBpbnN0YWxsZXIuYXBwbHkoc2VsZiwgW3NlbGZdLmNvbmNhdChhcmdzKSk7XG4gICAgfSk7XG4gIH0sXG5cbiAgX3BhcnNlRFNOOiBmdW5jdGlvbihzdHIpIHtcbiAgICB2YXIgbSA9IGRzblBhdHRlcm4uZXhlYyhzdHIpLFxuICAgICAgZHNuID0ge30sXG4gICAgICBpID0gNztcblxuICAgIHRyeSB7XG4gICAgICB3aGlsZSAoaS0tKSBkc25bZHNuS2V5c1tpXV0gPSBtW2ldIHx8ICcnO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIHRocm93IG5ldyBSYXZlbkNvbmZpZ0Vycm9yKCdJbnZhbGlkIERTTjogJyArIHN0cik7XG4gICAgfVxuXG4gICAgaWYgKGRzbi5wYXNzICYmICF0aGlzLl9nbG9iYWxPcHRpb25zLmFsbG93U2VjcmV0S2V5KSB7XG4gICAgICB0aHJvdyBuZXcgUmF2ZW5Db25maWdFcnJvcihcbiAgICAgICAgJ0RvIG5vdCBzcGVjaWZ5IHlvdXIgc2VjcmV0IGtleSBpbiB0aGUgRFNOLiBTZWU6IGh0dHA6Ly9iaXQubHkvcmF2ZW4tc2VjcmV0LWtleSdcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGRzbjtcbiAgfSxcblxuICBfZ2V0R2xvYmFsU2VydmVyOiBmdW5jdGlvbih1cmkpIHtcbiAgICAvLyBhc3NlbWJsZSB0aGUgZW5kcG9pbnQgZnJvbSB0aGUgdXJpIHBpZWNlc1xuICAgIHZhciBnbG9iYWxTZXJ2ZXIgPSAnLy8nICsgdXJpLmhvc3QgKyAodXJpLnBvcnQgPyAnOicgKyB1cmkucG9ydCA6ICcnKTtcblxuICAgIGlmICh1cmkucHJvdG9jb2wpIHtcbiAgICAgIGdsb2JhbFNlcnZlciA9IHVyaS5wcm90b2NvbCArICc6JyArIGdsb2JhbFNlcnZlcjtcbiAgICB9XG4gICAgcmV0dXJuIGdsb2JhbFNlcnZlcjtcbiAgfSxcblxuICBfaGFuZGxlT25FcnJvclN0YWNrSW5mbzogZnVuY3Rpb24oKSB7XG4gICAgLy8gaWYgd2UgYXJlIGludGVudGlvbmFsbHkgaWdub3JpbmcgZXJyb3JzIHZpYSBvbmVycm9yLCBiYWlsIG91dFxuICAgIGlmICghdGhpcy5faWdub3JlT25FcnJvcikge1xuICAgICAgdGhpcy5faGFuZGxlU3RhY2tJbmZvLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG4gICAgfVxuICB9LFxuXG4gIF9oYW5kbGVTdGFja0luZm86IGZ1bmN0aW9uKHN0YWNrSW5mbywgb3B0aW9ucykge1xuICAgIHZhciBmcmFtZXMgPSB0aGlzLl9wcmVwYXJlRnJhbWVzKHN0YWNrSW5mbywgb3B0aW9ucyk7XG5cbiAgICB0aGlzLl90cmlnZ2VyRXZlbnQoJ2hhbmRsZScsIHtcbiAgICAgIHN0YWNrSW5mbzogc3RhY2tJbmZvLFxuICAgICAgb3B0aW9uczogb3B0aW9uc1xuICAgIH0pO1xuXG4gICAgdGhpcy5fcHJvY2Vzc0V4Y2VwdGlvbihcbiAgICAgIHN0YWNrSW5mby5uYW1lLFxuICAgICAgc3RhY2tJbmZvLm1lc3NhZ2UsXG4gICAgICBzdGFja0luZm8udXJsLFxuICAgICAgc3RhY2tJbmZvLmxpbmVubyxcbiAgICAgIGZyYW1lcyxcbiAgICAgIG9wdGlvbnNcbiAgICApO1xuICB9LFxuXG4gIF9wcmVwYXJlRnJhbWVzOiBmdW5jdGlvbihzdGFja0luZm8sIG9wdGlvbnMpIHtcbiAgICB2YXIgc2VsZiA9IHRoaXM7XG4gICAgdmFyIGZyYW1lcyA9IFtdO1xuICAgIGlmIChzdGFja0luZm8uc3RhY2sgJiYgc3RhY2tJbmZvLnN0YWNrLmxlbmd0aCkge1xuICAgICAgZWFjaChzdGFja0luZm8uc3RhY2ssIGZ1bmN0aW9uKGksIHN0YWNrKSB7XG4gICAgICAgIHZhciBmcmFtZSA9IHNlbGYuX25vcm1hbGl6ZUZyYW1lKHN0YWNrLCBzdGFja0luZm8udXJsKTtcbiAgICAgICAgaWYgKGZyYW1lKSB7XG4gICAgICAgICAgZnJhbWVzLnB1c2goZnJhbWUpO1xuICAgICAgICB9XG4gICAgICB9KTtcblxuICAgICAgLy8gZS5nLiBmcmFtZXMgY2FwdHVyZWQgdmlhIGNhcHR1cmVNZXNzYWdlIHRocm93XG4gICAgICBpZiAob3B0aW9ucyAmJiBvcHRpb25zLnRyaW1IZWFkRnJhbWVzKSB7XG4gICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgb3B0aW9ucy50cmltSGVhZEZyYW1lcyAmJiBqIDwgZnJhbWVzLmxlbmd0aDsgaisrKSB7XG4gICAgICAgICAgZnJhbWVzW2pdLmluX2FwcCA9IGZhbHNlO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIGZyYW1lcyA9IGZyYW1lcy5zbGljZSgwLCB0aGlzLl9nbG9iYWxPcHRpb25zLnN0YWNrVHJhY2VMaW1pdCk7XG4gICAgcmV0dXJuIGZyYW1lcztcbiAgfSxcblxuICBfbm9ybWFsaXplRnJhbWU6IGZ1bmN0aW9uKGZyYW1lLCBzdGFja0luZm9VcmwpIHtcbiAgICAvLyBub3JtYWxpemUgdGhlIGZyYW1lcyBkYXRhXG4gICAgdmFyIG5vcm1hbGl6ZWQgPSB7XG4gICAgICBmaWxlbmFtZTogZnJhbWUudXJsLFxuICAgICAgbGluZW5vOiBmcmFtZS5saW5lLFxuICAgICAgY29sbm86IGZyYW1lLmNvbHVtbixcbiAgICAgIGZ1bmN0aW9uOiBmcmFtZS5mdW5jIHx8ICc/J1xuICAgIH07XG5cbiAgICAvLyBDYXNlIHdoZW4gd2UgZG9uJ3QgaGF2ZSBhbnkgaW5mb3JtYXRpb24gYWJvdXQgdGhlIGVycm9yXG4gICAgLy8gRS5nLiB0aHJvd2luZyBhIHN0cmluZyBvciByYXcgb2JqZWN0LCBpbnN0ZWFkIG9mIGFuIGBFcnJvcmAgaW4gRmlyZWZveFxuICAgIC8vIEdlbmVyYXRpbmcgc3ludGhldGljIGVycm9yIGRvZXNuJ3QgYWRkIGFueSB2YWx1ZSBoZXJlXG4gICAgLy9cbiAgICAvLyBXZSBzaG91bGQgcHJvYmFibHkgc29tZWhvdyBsZXQgYSB1c2VyIGtub3cgdGhhdCB0aGV5IHNob3VsZCBmaXggdGhlaXIgY29kZVxuICAgIGlmICghZnJhbWUudXJsKSB7XG4gICAgICBub3JtYWxpemVkLmZpbGVuYW1lID0gc3RhY2tJbmZvVXJsOyAvLyBmYWxsYmFjayB0byB3aG9sZSBzdGFja3MgdXJsIGZyb20gb25lcnJvciBoYW5kbGVyXG4gICAgfVxuXG4gICAgbm9ybWFsaXplZC5pbl9hcHAgPSAhLy8gZGV0ZXJtaW5lIGlmIGFuIGV4Y2VwdGlvbiBjYW1lIGZyb20gb3V0c2lkZSBvZiBvdXIgYXBwXG4gICAgLy8gZmlyc3Qgd2UgY2hlY2sgdGhlIGdsb2JhbCBpbmNsdWRlUGF0aHMgbGlzdC5cbiAgICAoXG4gICAgICAoISF0aGlzLl9nbG9iYWxPcHRpb25zLmluY2x1ZGVQYXRocy50ZXN0ICYmXG4gICAgICAgICF0aGlzLl9nbG9iYWxPcHRpb25zLmluY2x1ZGVQYXRocy50ZXN0KG5vcm1hbGl6ZWQuZmlsZW5hbWUpKSB8fFxuICAgICAgLy8gTm93IHdlIGNoZWNrIGZvciBmdW4sIGlmIHRoZSBmdW5jdGlvbiBuYW1lIGlzIFJhdmVuIG9yIFRyYWNlS2l0XG4gICAgICAvKFJhdmVufFRyYWNlS2l0KVxcLi8udGVzdChub3JtYWxpemVkWydmdW5jdGlvbiddKSB8fFxuICAgICAgLy8gZmluYWxseSwgd2UgZG8gYSBsYXN0IGRpdGNoIGVmZm9ydCBhbmQgY2hlY2sgZm9yIHJhdmVuLm1pbi5qc1xuICAgICAgL3JhdmVuXFwuKG1pblxcLik/anMkLy50ZXN0KG5vcm1hbGl6ZWQuZmlsZW5hbWUpXG4gICAgKTtcblxuICAgIHJldHVybiBub3JtYWxpemVkO1xuICB9LFxuXG4gIF9wcm9jZXNzRXhjZXB0aW9uOiBmdW5jdGlvbih0eXBlLCBtZXNzYWdlLCBmaWxldXJsLCBsaW5lbm8sIGZyYW1lcywgb3B0aW9ucykge1xuICAgIHZhciBwcmVmaXhlZE1lc3NhZ2UgPSAodHlwZSA/IHR5cGUgKyAnOiAnIDogJycpICsgKG1lc3NhZ2UgfHwgJycpO1xuICAgIGlmIChcbiAgICAgICEhdGhpcy5fZ2xvYmFsT3B0aW9ucy5pZ25vcmVFcnJvcnMudGVzdCAmJlxuICAgICAgKHRoaXMuX2dsb2JhbE9wdGlvbnMuaWdub3JlRXJyb3JzLnRlc3QobWVzc2FnZSkgfHxcbiAgICAgICAgdGhpcy5fZ2xvYmFsT3B0aW9ucy5pZ25vcmVFcnJvcnMudGVzdChwcmVmaXhlZE1lc3NhZ2UpKVxuICAgICkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHZhciBzdGFja3RyYWNlO1xuXG4gICAgaWYgKGZyYW1lcyAmJiBmcmFtZXMubGVuZ3RoKSB7XG4gICAgICBmaWxldXJsID0gZnJhbWVzWzBdLmZpbGVuYW1lIHx8IGZpbGV1cmw7XG4gICAgICAvLyBTZW50cnkgZXhwZWN0cyBmcmFtZXMgb2xkZXN0IHRvIG5ld2VzdFxuICAgICAgLy8gYW5kIEpTIHNlbmRzIHRoZW0gYXMgbmV3ZXN0IHRvIG9sZGVzdFxuICAgICAgZnJhbWVzLnJldmVyc2UoKTtcbiAgICAgIHN0YWNrdHJhY2UgPSB7ZnJhbWVzOiBmcmFtZXN9O1xuICAgIH0gZWxzZSBpZiAoZmlsZXVybCkge1xuICAgICAgc3RhY2t0cmFjZSA9IHtcbiAgICAgICAgZnJhbWVzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgZmlsZW5hbWU6IGZpbGV1cmwsXG4gICAgICAgICAgICBsaW5lbm86IGxpbmVubyxcbiAgICAgICAgICAgIGluX2FwcDogdHJ1ZVxuICAgICAgICAgIH1cbiAgICAgICAgXVxuICAgICAgfTtcbiAgICB9XG5cbiAgICBpZiAoXG4gICAgICAhIXRoaXMuX2dsb2JhbE9wdGlvbnMuaWdub3JlVXJscy50ZXN0ICYmXG4gICAgICB0aGlzLl9nbG9iYWxPcHRpb25zLmlnbm9yZVVybHMudGVzdChmaWxldXJsKVxuICAgICkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGlmIChcbiAgICAgICEhdGhpcy5fZ2xvYmFsT3B0aW9ucy53aGl0ZWxpc3RVcmxzLnRlc3QgJiZcbiAgICAgICF0aGlzLl9nbG9iYWxPcHRpb25zLndoaXRlbGlzdFVybHMudGVzdChmaWxldXJsKVxuICAgICkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHZhciBkYXRhID0gb2JqZWN0TWVyZ2UoXG4gICAgICB7XG4gICAgICAgIC8vIHNlbnRyeS5pbnRlcmZhY2VzLkV4Y2VwdGlvblxuICAgICAgICBleGNlcHRpb246IHtcbiAgICAgICAgICB2YWx1ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgdHlwZTogdHlwZSxcbiAgICAgICAgICAgICAgdmFsdWU6IG1lc3NhZ2UsXG4gICAgICAgICAgICAgIHN0YWNrdHJhY2U6IHN0YWNrdHJhY2VcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0sXG4gICAgICAgIGN1bHByaXQ6IGZpbGV1cmxcbiAgICAgIH0sXG4gICAgICBvcHRpb25zXG4gICAgKTtcblxuICAgIC8vIEZpcmUgYXdheSFcbiAgICB0aGlzLl9zZW5kKGRhdGEpO1xuICB9LFxuXG4gIF90cmltUGFja2V0OiBmdW5jdGlvbihkYXRhKSB7XG4gICAgLy8gRm9yIG5vdywgd2Ugb25seSB3YW50IHRvIHRydW5jYXRlIHRoZSB0d28gZGlmZmVyZW50IG1lc3NhZ2VzXG4gICAgLy8gYnV0IHRoaXMgY291bGQvc2hvdWxkIGJlIGV4cGFuZGVkIHRvIGp1c3QgdHJpbSBldmVyeXRoaW5nXG4gICAgdmFyIG1heCA9IHRoaXMuX2dsb2JhbE9wdGlvbnMubWF4TWVzc2FnZUxlbmd0aDtcbiAgICBpZiAoZGF0YS5tZXNzYWdlKSB7XG4gICAgICBkYXRhLm1lc3NhZ2UgPSB0cnVuY2F0ZShkYXRhLm1lc3NhZ2UsIG1heCk7XG4gICAgfVxuICAgIGlmIChkYXRhLmV4Y2VwdGlvbikge1xuICAgICAgdmFyIGV4Y2VwdGlvbiA9IGRhdGEuZXhjZXB0aW9uLnZhbHVlc1swXTtcbiAgICAgIGV4Y2VwdGlvbi52YWx1ZSA9IHRydW5jYXRlKGV4Y2VwdGlvbi52YWx1ZSwgbWF4KTtcbiAgICB9XG5cbiAgICB2YXIgcmVxdWVzdCA9IGRhdGEucmVxdWVzdDtcbiAgICBpZiAocmVxdWVzdCkge1xuICAgICAgaWYgKHJlcXVlc3QudXJsKSB7XG4gICAgICAgIHJlcXVlc3QudXJsID0gdHJ1bmNhdGUocmVxdWVzdC51cmwsIHRoaXMuX2dsb2JhbE9wdGlvbnMubWF4VXJsTGVuZ3RoKTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXF1ZXN0LlJlZmVyZXIpIHtcbiAgICAgICAgcmVxdWVzdC5SZWZlcmVyID0gdHJ1bmNhdGUocmVxdWVzdC5SZWZlcmVyLCB0aGlzLl9nbG9iYWxPcHRpb25zLm1heFVybExlbmd0aCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKGRhdGEuYnJlYWRjcnVtYnMgJiYgZGF0YS5icmVhZGNydW1icy52YWx1ZXMpXG4gICAgICB0aGlzLl90cmltQnJlYWRjcnVtYnMoZGF0YS5icmVhZGNydW1icyk7XG5cbiAgICByZXR1cm4gZGF0YTtcbiAgfSxcblxuICAvKipcbiAgICAgKiBUcnVuY2F0ZSBicmVhZGNydW1iIHZhbHVlcyAocmlnaHQgbm93IGp1c3QgVVJMcylcbiAgICAgKi9cbiAgX3RyaW1CcmVhZGNydW1iczogZnVuY3Rpb24oYnJlYWRjcnVtYnMpIHtcbiAgICAvLyBrbm93biBicmVhZGNydW1iIHByb3BlcnRpZXMgd2l0aCB1cmxzXG4gICAgLy8gVE9ETzogYWxzbyBjb25zaWRlciBhcmJpdHJhcnkgcHJvcCB2YWx1ZXMgdGhhdCBzdGFydCB3aXRoIChodHRwcz8pPzovL1xuICAgIHZhciB1cmxQcm9wcyA9IFsndG8nLCAnZnJvbScsICd1cmwnXSxcbiAgICAgIHVybFByb3AsXG4gICAgICBjcnVtYixcbiAgICAgIGRhdGE7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJyZWFkY3J1bWJzLnZhbHVlcy5sZW5ndGg7ICsraSkge1xuICAgICAgY3J1bWIgPSBicmVhZGNydW1icy52YWx1ZXNbaV07XG4gICAgICBpZiAoXG4gICAgICAgICFjcnVtYi5oYXNPd25Qcm9wZXJ0eSgnZGF0YScpIHx8XG4gICAgICAgICFpc09iamVjdChjcnVtYi5kYXRhKSB8fFxuICAgICAgICBvYmplY3RGcm96ZW4oY3J1bWIuZGF0YSlcbiAgICAgIClcbiAgICAgICAgY29udGludWU7XG5cbiAgICAgIGRhdGEgPSBvYmplY3RNZXJnZSh7fSwgY3J1bWIuZGF0YSk7XG4gICAgICBmb3IgKHZhciBqID0gMDsgaiA8IHVybFByb3BzLmxlbmd0aDsgKytqKSB7XG4gICAgICAgIHVybFByb3AgPSB1cmxQcm9wc1tqXTtcbiAgICAgICAgaWYgKGRhdGEuaGFzT3duUHJvcGVydHkodXJsUHJvcCkgJiYgZGF0YVt1cmxQcm9wXSkge1xuICAgICAgICAgIGRhdGFbdXJsUHJvcF0gPSB0cnVuY2F0ZShkYXRhW3VybFByb3BdLCB0aGlzLl9nbG9iYWxPcHRpb25zLm1heFVybExlbmd0aCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGJyZWFkY3J1bWJzLnZhbHVlc1tpXS5kYXRhID0gZGF0YTtcbiAgICB9XG4gIH0sXG5cbiAgX2dldEh0dHBEYXRhOiBmdW5jdGlvbigpIHtcbiAgICBpZiAoIXRoaXMuX2hhc05hdmlnYXRvciAmJiAhdGhpcy5faGFzRG9jdW1lbnQpIHJldHVybjtcbiAgICB2YXIgaHR0cERhdGEgPSB7fTtcblxuICAgIGlmICh0aGlzLl9oYXNOYXZpZ2F0b3IgJiYgX25hdmlnYXRvci51c2VyQWdlbnQpIHtcbiAgICAgIGh0dHBEYXRhLmhlYWRlcnMgPSB7XG4gICAgICAgICdVc2VyLUFnZW50JzogbmF2aWdhdG9yLnVzZXJBZ2VudFxuICAgICAgfTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5faGFzRG9jdW1lbnQpIHtcbiAgICAgIGlmIChfZG9jdW1lbnQubG9jYXRpb24gJiYgX2RvY3VtZW50LmxvY2F0aW9uLmhyZWYpIHtcbiAgICAgICAgaHR0cERhdGEudXJsID0gX2RvY3VtZW50LmxvY2F0aW9uLmhyZWY7XG4gICAgICB9XG4gICAgICBpZiAoX2RvY3VtZW50LnJlZmVycmVyKSB7XG4gICAgICAgIGlmICghaHR0cERhdGEuaGVhZGVycykgaHR0cERhdGEuaGVhZGVycyA9IHt9O1xuICAgICAgICBodHRwRGF0YS5oZWFkZXJzLlJlZmVyZXIgPSBfZG9jdW1lbnQucmVmZXJyZXI7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIGh0dHBEYXRhO1xuICB9LFxuXG4gIF9yZXNldEJhY2tvZmY6IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMuX2JhY2tvZmZEdXJhdGlvbiA9IDA7XG4gICAgdGhpcy5fYmFja29mZlN0YXJ0ID0gbnVsbDtcbiAgfSxcblxuICBfc2hvdWxkQmFja29mZjogZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuX2JhY2tvZmZEdXJhdGlvbiAmJiBub3coKSAtIHRoaXMuX2JhY2tvZmZTdGFydCA8IHRoaXMuX2JhY2tvZmZEdXJhdGlvbjtcbiAgfSxcblxuICAvKipcbiAgICAgKiBSZXR1cm5zIHRydWUgaWYgdGhlIGluLXByb2Nlc3MgZGF0YSBwYXlsb2FkIG1hdGNoZXMgdGhlIHNpZ25hdHVyZVxuICAgICAqIG9mIHRoZSBwcmV2aW91c2x5LXNlbnQgZGF0YVxuICAgICAqXG4gICAgICogTk9URTogVGhpcyBoYXMgdG8gYmUgZG9uZSBhdCB0aGlzIGxldmVsIGJlY2F1c2UgVHJhY2VLaXQgY2FuIGdlbmVyYXRlXG4gICAgICogICAgICAgZGF0YSBmcm9tIHdpbmRvdy5vbmVycm9yIFdJVEhPVVQgYW4gZXhjZXB0aW9uIG9iamVjdCAoSUU4LCBJRTksXG4gICAgICogICAgICAgb3RoZXIgb2xkIGJyb3dzZXJzKS4gVGhpcyBjYW4gdGFrZSB0aGUgZm9ybSBvZiBhbiBcImV4Y2VwdGlvblwiXG4gICAgICogICAgICAgZGF0YSBvYmplY3Qgd2l0aCBhIHNpbmdsZSBmcmFtZSAoZGVyaXZlZCBmcm9tIHRoZSBvbmVycm9yIGFyZ3MpLlxuICAgICAqL1xuICBfaXNSZXBlYXREYXRhOiBmdW5jdGlvbihjdXJyZW50KSB7XG4gICAgdmFyIGxhc3QgPSB0aGlzLl9sYXN0RGF0YTtcblxuICAgIGlmIChcbiAgICAgICFsYXN0IHx8XG4gICAgICBjdXJyZW50Lm1lc3NhZ2UgIT09IGxhc3QubWVzc2FnZSB8fCAvLyBkZWZpbmVkIGZvciBjYXB0dXJlTWVzc2FnZVxuICAgICAgY3VycmVudC5jdWxwcml0ICE9PSBsYXN0LmN1bHByaXQgLy8gZGVmaW5lZCBmb3IgY2FwdHVyZUV4Y2VwdGlvbi9vbmVycm9yXG4gICAgKVxuICAgICAgcmV0dXJuIGZhbHNlO1xuXG4gICAgLy8gU3RhY2t0cmFjZSBpbnRlcmZhY2UgKGkuZS4gZnJvbSBjYXB0dXJlTWVzc2FnZSlcbiAgICBpZiAoY3VycmVudC5zdGFja3RyYWNlIHx8IGxhc3Quc3RhY2t0cmFjZSkge1xuICAgICAgcmV0dXJuIGlzU2FtZVN0YWNrdHJhY2UoY3VycmVudC5zdGFja3RyYWNlLCBsYXN0LnN0YWNrdHJhY2UpO1xuICAgIH0gZWxzZSBpZiAoY3VycmVudC5leGNlcHRpb24gfHwgbGFzdC5leGNlcHRpb24pIHtcbiAgICAgIC8vIEV4Y2VwdGlvbiBpbnRlcmZhY2UgKGkuZS4gZnJvbSBjYXB0dXJlRXhjZXB0aW9uL29uZXJyb3IpXG4gICAgICByZXR1cm4gaXNTYW1lRXhjZXB0aW9uKGN1cnJlbnQuZXhjZXB0aW9uLCBsYXN0LmV4Y2VwdGlvbik7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG4gIH0sXG5cbiAgX3NldEJhY2tvZmZTdGF0ZTogZnVuY3Rpb24ocmVxdWVzdCkge1xuICAgIC8vIElmIHdlIGFyZSBhbHJlYWR5IGluIGEgYmFja29mZiBzdGF0ZSwgZG9uJ3QgY2hhbmdlIGFueXRoaW5nXG4gICAgaWYgKHRoaXMuX3Nob3VsZEJhY2tvZmYoKSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIHZhciBzdGF0dXMgPSByZXF1ZXN0LnN0YXR1cztcblxuICAgIC8vIDQwMCAtIHByb2plY3RfaWQgZG9lc24ndCBleGlzdCBvciBzb21lIG90aGVyIGZhdGFsXG4gICAgLy8gNDAxIC0gaW52YWxpZC9yZXZva2VkIGRzblxuICAgIC8vIDQyOSAtIHRvbyBtYW55IHJlcXVlc3RzXG4gICAgaWYgKCEoc3RhdHVzID09PSA0MDAgfHwgc3RhdHVzID09PSA0MDEgfHwgc3RhdHVzID09PSA0MjkpKSByZXR1cm47XG5cbiAgICB2YXIgcmV0cnk7XG4gICAgdHJ5IHtcbiAgICAgIC8vIElmIFJldHJ5LUFmdGVyIGlzIG5vdCBpbiBBY2Nlc3MtQ29udHJvbC1FeHBvc2UtSGVhZGVycywgbW9zdFxuICAgICAgLy8gYnJvd3NlcnMgd2lsbCB0aHJvdyBhbiBleGNlcHRpb24gdHJ5aW5nIHRvIGFjY2VzcyBpdFxuICAgICAgcmV0cnkgPSByZXF1ZXN0LmdldFJlc3BvbnNlSGVhZGVyKCdSZXRyeS1BZnRlcicpO1xuICAgICAgcmV0cnkgPSBwYXJzZUludChyZXRyeSwgMTApICogMTAwMDsgLy8gUmV0cnktQWZ0ZXIgaXMgcmV0dXJuZWQgaW4gc2Vjb25kc1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIC8qIGVzbGludCBuby1lbXB0eTowICovXG4gICAgfVxuXG4gICAgdGhpcy5fYmFja29mZkR1cmF0aW9uID0gcmV0cnlcbiAgICAgID8gLy8gSWYgU2VudHJ5IHNlcnZlciByZXR1cm5lZCBhIFJldHJ5LUFmdGVyIHZhbHVlLCB1c2UgaXRcbiAgICAgICAgcmV0cnlcbiAgICAgIDogLy8gT3RoZXJ3aXNlLCBkb3VibGUgdGhlIGxhc3QgYmFja29mZiBkdXJhdGlvbiAoc3RhcnRzIGF0IDEgc2VjKVxuICAgICAgICB0aGlzLl9iYWNrb2ZmRHVyYXRpb24gKiAyIHx8IDEwMDA7XG5cbiAgICB0aGlzLl9iYWNrb2ZmU3RhcnQgPSBub3coKTtcbiAgfSxcblxuICBfc2VuZDogZnVuY3Rpb24oZGF0YSkge1xuICAgIHZhciBnbG9iYWxPcHRpb25zID0gdGhpcy5fZ2xvYmFsT3B0aW9ucztcblxuICAgIHZhciBiYXNlRGF0YSA9IHtcbiAgICAgICAgcHJvamVjdDogdGhpcy5fZ2xvYmFsUHJvamVjdCxcbiAgICAgICAgbG9nZ2VyOiBnbG9iYWxPcHRpb25zLmxvZ2dlcixcbiAgICAgICAgcGxhdGZvcm06ICdqYXZhc2NyaXB0J1xuICAgICAgfSxcbiAgICAgIGh0dHBEYXRhID0gdGhpcy5fZ2V0SHR0cERhdGEoKTtcblxuICAgIGlmIChodHRwRGF0YSkge1xuICAgICAgYmFzZURhdGEucmVxdWVzdCA9IGh0dHBEYXRhO1xuICAgIH1cblxuICAgIC8vIEhBQ0s6IGRlbGV0ZSBgdHJpbUhlYWRGcmFtZXNgIHRvIHByZXZlbnQgZnJvbSBhcHBlYXJpbmcgaW4gb3V0Ym91bmQgcGF5bG9hZFxuICAgIGlmIChkYXRhLnRyaW1IZWFkRnJhbWVzKSBkZWxldGUgZGF0YS50cmltSGVhZEZyYW1lcztcblxuICAgIGRhdGEgPSBvYmplY3RNZXJnZShiYXNlRGF0YSwgZGF0YSk7XG5cbiAgICAvLyBNZXJnZSBpbiB0aGUgdGFncyBhbmQgZXh0cmEgc2VwYXJhdGVseSBzaW5jZSBvYmplY3RNZXJnZSBkb2Vzbid0IGhhbmRsZSBhIGRlZXAgbWVyZ2VcbiAgICBkYXRhLnRhZ3MgPSBvYmplY3RNZXJnZShvYmplY3RNZXJnZSh7fSwgdGhpcy5fZ2xvYmFsQ29udGV4dC50YWdzKSwgZGF0YS50YWdzKTtcbiAgICBkYXRhLmV4dHJhID0gb2JqZWN0TWVyZ2Uob2JqZWN0TWVyZ2Uoe30sIHRoaXMuX2dsb2JhbENvbnRleHQuZXh0cmEpLCBkYXRhLmV4dHJhKTtcblxuICAgIC8vIFNlbmQgYWxvbmcgb3VyIG93biBjb2xsZWN0ZWQgbWV0YWRhdGEgd2l0aCBleHRyYVxuICAgIGRhdGEuZXh0cmFbJ3Nlc3Npb246ZHVyYXRpb24nXSA9IG5vdygpIC0gdGhpcy5fc3RhcnRUaW1lO1xuXG4gICAgaWYgKHRoaXMuX2JyZWFkY3J1bWJzICYmIHRoaXMuX2JyZWFkY3J1bWJzLmxlbmd0aCA+IDApIHtcbiAgICAgIC8vIGludGVudGlvbmFsbHkgbWFrZSBzaGFsbG93IGNvcHkgc28gdGhhdCBhZGRpdGlvbnNcbiAgICAgIC8vIHRvIGJyZWFkY3J1bWJzIGFyZW4ndCBhY2NpZGVudGFsbHkgc2VudCBpbiB0aGlzIHJlcXVlc3RcbiAgICAgIGRhdGEuYnJlYWRjcnVtYnMgPSB7XG4gICAgICAgIHZhbHVlczogW10uc2xpY2UuY2FsbCh0aGlzLl9icmVhZGNydW1icywgMClcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gSWYgdGhlcmUgYXJlIG5vIHRhZ3MvZXh0cmEsIHN0cmlwIHRoZSBrZXkgZnJvbSB0aGUgcGF5bG9hZCBhbGx0b2d0aGVyLlxuICAgIGlmIChpc0VtcHR5T2JqZWN0KGRhdGEudGFncykpIGRlbGV0ZSBkYXRhLnRhZ3M7XG5cbiAgICBpZiAodGhpcy5fZ2xvYmFsQ29udGV4dC51c2VyKSB7XG4gICAgICAvLyBzZW50cnkuaW50ZXJmYWNlcy5Vc2VyXG4gICAgICBkYXRhLnVzZXIgPSB0aGlzLl9nbG9iYWxDb250ZXh0LnVzZXI7XG4gICAgfVxuXG4gICAgLy8gSW5jbHVkZSB0aGUgZW52aXJvbm1lbnQgaWYgaXQncyBkZWZpbmVkIGluIGdsb2JhbE9wdGlvbnNcbiAgICBpZiAoZ2xvYmFsT3B0aW9ucy5lbnZpcm9ubWVudCkgZGF0YS5lbnZpcm9ubWVudCA9IGdsb2JhbE9wdGlvbnMuZW52aXJvbm1lbnQ7XG5cbiAgICAvLyBJbmNsdWRlIHRoZSByZWxlYXNlIGlmIGl0J3MgZGVmaW5lZCBpbiBnbG9iYWxPcHRpb25zXG4gICAgaWYgKGdsb2JhbE9wdGlvbnMucmVsZWFzZSkgZGF0YS5yZWxlYXNlID0gZ2xvYmFsT3B0aW9ucy5yZWxlYXNlO1xuXG4gICAgLy8gSW5jbHVkZSBzZXJ2ZXJfbmFtZSBpZiBpdCdzIGRlZmluZWQgaW4gZ2xvYmFsT3B0aW9uc1xuICAgIGlmIChnbG9iYWxPcHRpb25zLnNlcnZlck5hbWUpIGRhdGEuc2VydmVyX25hbWUgPSBnbG9iYWxPcHRpb25zLnNlcnZlck5hbWU7XG5cbiAgICBpZiAoaXNGdW5jdGlvbihnbG9iYWxPcHRpb25zLmRhdGFDYWxsYmFjaykpIHtcbiAgICAgIGRhdGEgPSBnbG9iYWxPcHRpb25zLmRhdGFDYWxsYmFjayhkYXRhKSB8fCBkYXRhO1xuICAgIH1cblxuICAgIC8vIFdoeT8/Pz8/Pz8/Pz9cbiAgICBpZiAoIWRhdGEgfHwgaXNFbXB0eU9iamVjdChkYXRhKSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIENoZWNrIGlmIHRoZSByZXF1ZXN0IHNob3VsZCBiZSBmaWx0ZXJlZCBvciBub3RcbiAgICBpZiAoXG4gICAgICBpc0Z1bmN0aW9uKGdsb2JhbE9wdGlvbnMuc2hvdWxkU2VuZENhbGxiYWNrKSAmJlxuICAgICAgIWdsb2JhbE9wdGlvbnMuc2hvdWxkU2VuZENhbGxiYWNrKGRhdGEpXG4gICAgKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQmFja29mZiBzdGF0ZTogU2VudHJ5IHNlcnZlciBwcmV2aW91c2x5IHJlc3BvbmRlZCB3LyBhbiBlcnJvciAoZS5nLiA0MjkgLSB0b28gbWFueSByZXF1ZXN0cyksXG4gICAgLy8gc28gZHJvcCByZXF1ZXN0cyB1bnRpbCBcImNvb2wtb2ZmXCIgcGVyaW9kIGhhcyBlbGFwc2VkLlxuICAgIGlmICh0aGlzLl9zaG91bGRCYWNrb2ZmKCkpIHtcbiAgICAgIHRoaXMuX2xvZ0RlYnVnKCd3YXJuJywgJ1JhdmVuIGRyb3BwZWQgZXJyb3IgZHVlIHRvIGJhY2tvZmY6ICcsIGRhdGEpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZ2xvYmFsT3B0aW9ucy5zYW1wbGVSYXRlID09PSAnbnVtYmVyJykge1xuICAgICAgaWYgKE1hdGgucmFuZG9tKCkgPCBnbG9iYWxPcHRpb25zLnNhbXBsZVJhdGUpIHtcbiAgICAgICAgdGhpcy5fc2VuZFByb2Nlc3NlZFBheWxvYWQoZGF0YSk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuX3NlbmRQcm9jZXNzZWRQYXlsb2FkKGRhdGEpO1xuICAgIH1cbiAgfSxcblxuICBfZ2V0VXVpZDogZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHV1aWQ0KCk7XG4gIH0sXG5cbiAgX3NlbmRQcm9jZXNzZWRQYXlsb2FkOiBmdW5jdGlvbihkYXRhLCBjYWxsYmFjaykge1xuICAgIHZhciBzZWxmID0gdGhpcztcbiAgICB2YXIgZ2xvYmFsT3B0aW9ucyA9IHRoaXMuX2dsb2JhbE9wdGlvbnM7XG5cbiAgICBpZiAoIXRoaXMuaXNTZXR1cCgpKSByZXR1cm47XG5cbiAgICAvLyBUcnkgYW5kIGNsZWFuIHVwIHRoZSBwYWNrZXQgYmVmb3JlIHNlbmRpbmcgYnkgdHJ1bmNhdGluZyBsb25nIHZhbHVlc1xuICAgIGRhdGEgPSB0aGlzLl90cmltUGFja2V0KGRhdGEpO1xuXG4gICAgLy8gaWRlYWxseSBkdXBsaWNhdGUgZXJyb3IgdGVzdGluZyBzaG91bGQgb2NjdXIgKmJlZm9yZSogZGF0YUNhbGxiYWNrL3Nob3VsZFNlbmRDYWxsYmFjayxcbiAgICAvLyBidXQgdGhpcyB3b3VsZCByZXF1aXJlIGNvcHlpbmcgYW4gdW4tdHJ1bmNhdGVkIGNvcHkgb2YgdGhlIGRhdGEgcGFja2V0LCB3aGljaCBjYW4gYmVcbiAgICAvLyBhcmJpdHJhcmlseSBkZWVwIChleHRyYV9kYXRhKSAtLSBjb3VsZCBiZSB3b3J0aHdoaWxlPyB3aWxsIHJldmlzaXRcbiAgICBpZiAoIXRoaXMuX2dsb2JhbE9wdGlvbnMuYWxsb3dEdXBsaWNhdGVzICYmIHRoaXMuX2lzUmVwZWF0RGF0YShkYXRhKSkge1xuICAgICAgdGhpcy5fbG9nRGVidWcoJ3dhcm4nLCAnUmF2ZW4gZHJvcHBlZCByZXBlYXQgZXZlbnQ6ICcsIGRhdGEpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIFNlbmQgYWxvbmcgYW4gZXZlbnRfaWQgaWYgbm90IGV4cGxpY2l0bHkgcGFzc2VkLlxuICAgIC8vIFRoaXMgZXZlbnRfaWQgY2FuIGJlIHVzZWQgdG8gcmVmZXJlbmNlIHRoZSBlcnJvciB3aXRoaW4gU2VudHJ5IGl0c2VsZi5cbiAgICAvLyBTZXQgbGFzdEV2ZW50SWQgYWZ0ZXIgd2Uga25vdyB0aGUgZXJyb3Igc2hvdWxkIGFjdHVhbGx5IGJlIHNlbnRcbiAgICB0aGlzLl9sYXN0RXZlbnRJZCA9IGRhdGEuZXZlbnRfaWQgfHwgKGRhdGEuZXZlbnRfaWQgPSB0aGlzLl9nZXRVdWlkKCkpO1xuXG4gICAgLy8gU3RvcmUgb3V0Ym91bmQgcGF5bG9hZCBhZnRlciB0cmltXG4gICAgdGhpcy5fbGFzdERhdGEgPSBkYXRhO1xuXG4gICAgdGhpcy5fbG9nRGVidWcoJ2RlYnVnJywgJ1JhdmVuIGFib3V0IHRvIHNlbmQ6JywgZGF0YSk7XG5cbiAgICB2YXIgYXV0aCA9IHtcbiAgICAgIHNlbnRyeV92ZXJzaW9uOiAnNycsXG4gICAgICBzZW50cnlfY2xpZW50OiAncmF2ZW4tanMvJyArIHRoaXMuVkVSU0lPTixcbiAgICAgIHNlbnRyeV9rZXk6IHRoaXMuX2dsb2JhbEtleVxuICAgIH07XG5cbiAgICBpZiAodGhpcy5fZ2xvYmFsU2VjcmV0KSB7XG4gICAgICBhdXRoLnNlbnRyeV9zZWNyZXQgPSB0aGlzLl9nbG9iYWxTZWNyZXQ7XG4gICAgfVxuXG4gICAgdmFyIGV4Y2VwdGlvbiA9IGRhdGEuZXhjZXB0aW9uICYmIGRhdGEuZXhjZXB0aW9uLnZhbHVlc1swXTtcblxuICAgIC8vIG9ubHkgY2FwdHVyZSAnc2VudHJ5JyBicmVhZGNydW1iIGlzIGF1dG9CcmVhZGNydW1icyBpcyB0cnV0aHlcbiAgICBpZiAoXG4gICAgICB0aGlzLl9nbG9iYWxPcHRpb25zLmF1dG9CcmVhZGNydW1icyAmJlxuICAgICAgdGhpcy5fZ2xvYmFsT3B0aW9ucy5hdXRvQnJlYWRjcnVtYnMuc2VudHJ5XG4gICAgKSB7XG4gICAgICB0aGlzLmNhcHR1cmVCcmVhZGNydW1iKHtcbiAgICAgICAgY2F0ZWdvcnk6ICdzZW50cnknLFxuICAgICAgICBtZXNzYWdlOiBleGNlcHRpb25cbiAgICAgICAgICA/IChleGNlcHRpb24udHlwZSA/IGV4Y2VwdGlvbi50eXBlICsgJzogJyA6ICcnKSArIGV4Y2VwdGlvbi52YWx1ZVxuICAgICAgICAgIDogZGF0YS5tZXNzYWdlLFxuICAgICAgICBldmVudF9pZDogZGF0YS5ldmVudF9pZCxcbiAgICAgICAgbGV2ZWw6IGRhdGEubGV2ZWwgfHwgJ2Vycm9yJyAvLyBwcmVzdW1lIGVycm9yIHVubGVzcyBzcGVjaWZpZWRcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZhciB1cmwgPSB0aGlzLl9nbG9iYWxFbmRwb2ludDtcbiAgICAoZ2xvYmFsT3B0aW9ucy50cmFuc3BvcnQgfHwgdGhpcy5fbWFrZVJlcXVlc3QpLmNhbGwodGhpcywge1xuICAgICAgdXJsOiB1cmwsXG4gICAgICBhdXRoOiBhdXRoLFxuICAgICAgZGF0YTogZGF0YSxcbiAgICAgIG9wdGlvbnM6IGdsb2JhbE9wdGlvbnMsXG4gICAgICBvblN1Y2Nlc3M6IGZ1bmN0aW9uIHN1Y2Nlc3MoKSB7XG4gICAgICAgIHNlbGYuX3Jlc2V0QmFja29mZigpO1xuXG4gICAgICAgIHNlbGYuX3RyaWdnZXJFdmVudCgnc3VjY2VzcycsIHtcbiAgICAgICAgICBkYXRhOiBkYXRhLFxuICAgICAgICAgIHNyYzogdXJsXG4gICAgICAgIH0pO1xuICAgICAgICBjYWxsYmFjayAmJiBjYWxsYmFjaygpO1xuICAgICAgfSxcbiAgICAgIG9uRXJyb3I6IGZ1bmN0aW9uIGZhaWx1cmUoZXJyb3IpIHtcbiAgICAgICAgc2VsZi5fbG9nRGVidWcoJ2Vycm9yJywgJ1JhdmVuIHRyYW5zcG9ydCBmYWlsZWQgdG8gc2VuZDogJywgZXJyb3IpO1xuXG4gICAgICAgIGlmIChlcnJvci5yZXF1ZXN0KSB7XG4gICAgICAgICAgc2VsZi5fc2V0QmFja29mZlN0YXRlKGVycm9yLnJlcXVlc3QpO1xuICAgICAgICB9XG5cbiAgICAgICAgc2VsZi5fdHJpZ2dlckV2ZW50KCdmYWlsdXJlJywge1xuICAgICAgICAgIGRhdGE6IGRhdGEsXG4gICAgICAgICAgc3JjOiB1cmxcbiAgICAgICAgfSk7XG4gICAgICAgIGVycm9yID0gZXJyb3IgfHwgbmV3IEVycm9yKCdSYXZlbiBzZW5kIGZhaWxlZCAobm8gYWRkaXRpb25hbCBkZXRhaWxzIHByb3ZpZGVkKScpO1xuICAgICAgICBjYWxsYmFjayAmJiBjYWxsYmFjayhlcnJvcik7XG4gICAgICB9XG4gICAgfSk7XG4gIH0sXG5cbiAgX21ha2VSZXF1ZXN0OiBmdW5jdGlvbihvcHRzKSB7XG4gICAgdmFyIHJlcXVlc3QgPSBfd2luZG93LlhNTEh0dHBSZXF1ZXN0ICYmIG5ldyBfd2luZG93LlhNTEh0dHBSZXF1ZXN0KCk7XG4gICAgaWYgKCFyZXF1ZXN0KSByZXR1cm47XG5cbiAgICAvLyBpZiBicm93c2VyIGRvZXNuJ3Qgc3VwcG9ydCBDT1JTIChlLmcuIElFNyksIHdlIGFyZSBvdXQgb2YgbHVja1xuICAgIHZhciBoYXNDT1JTID0gJ3dpdGhDcmVkZW50aWFscycgaW4gcmVxdWVzdCB8fCB0eXBlb2YgWERvbWFpblJlcXVlc3QgIT09ICd1bmRlZmluZWQnO1xuXG4gICAgaWYgKCFoYXNDT1JTKSByZXR1cm47XG5cbiAgICB2YXIgdXJsID0gb3B0cy51cmw7XG5cbiAgICBpZiAoJ3dpdGhDcmVkZW50aWFscycgaW4gcmVxdWVzdCkge1xuICAgICAgcmVxdWVzdC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgaWYgKHJlcXVlc3QucmVhZHlTdGF0ZSAhPT0gNCkge1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfSBlbHNlIGlmIChyZXF1ZXN0LnN0YXR1cyA9PT0gMjAwKSB7XG4gICAgICAgICAgb3B0cy5vblN1Y2Nlc3MgJiYgb3B0cy5vblN1Y2Nlc3MoKTtcbiAgICAgICAgfSBlbHNlIGlmIChvcHRzLm9uRXJyb3IpIHtcbiAgICAgICAgICB2YXIgZXJyID0gbmV3IEVycm9yKCdTZW50cnkgZXJyb3IgY29kZTogJyArIHJlcXVlc3Quc3RhdHVzKTtcbiAgICAgICAgICBlcnIucmVxdWVzdCA9IHJlcXVlc3Q7XG4gICAgICAgICAgb3B0cy5vbkVycm9yKGVycik7XG4gICAgICAgIH1cbiAgICAgIH07XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlcXVlc3QgPSBuZXcgWERvbWFpblJlcXVlc3QoKTtcbiAgICAgIC8vIHhkb21haW5yZXF1ZXN0IGNhbm5vdCBnbyBodHRwIC0+IGh0dHBzIChvciB2aWNlIHZlcnNhKSxcbiAgICAgIC8vIHNvIGFsd2F5cyB1c2UgcHJvdG9jb2wgcmVsYXRpdmVcbiAgICAgIHVybCA9IHVybC5yZXBsYWNlKC9eaHR0cHM/Oi8sICcnKTtcblxuICAgICAgLy8gb25yZWFkeXN0YXRlY2hhbmdlIG5vdCBzdXBwb3J0ZWQgYnkgWERvbWFpblJlcXVlc3RcbiAgICAgIGlmIChvcHRzLm9uU3VjY2Vzcykge1xuICAgICAgICByZXF1ZXN0Lm9ubG9hZCA9IG9wdHMub25TdWNjZXNzO1xuICAgICAgfVxuICAgICAgaWYgKG9wdHMub25FcnJvcikge1xuICAgICAgICByZXF1ZXN0Lm9uZXJyb3IgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgICB2YXIgZXJyID0gbmV3IEVycm9yKCdTZW50cnkgZXJyb3IgY29kZTogWERvbWFpblJlcXVlc3QnKTtcbiAgICAgICAgICBlcnIucmVxdWVzdCA9IHJlcXVlc3Q7XG4gICAgICAgICAgb3B0cy5vbkVycm9yKGVycik7XG4gICAgICAgIH07XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gTk9URTogYXV0aCBpcyBpbnRlbnRpb25hbGx5IHNlbnQgYXMgcGFydCBvZiBxdWVyeSBzdHJpbmcgKE5PVCBhcyBjdXN0b21cbiAgICAvLyAgICAgICBIVFRQIGhlYWRlcikgc28gYXMgdG8gYXZvaWQgcHJlZmxpZ2h0IENPUlMgcmVxdWVzdHNcbiAgICByZXF1ZXN0Lm9wZW4oJ1BPU1QnLCB1cmwgKyAnPycgKyB1cmxlbmNvZGUob3B0cy5hdXRoKSk7XG4gICAgcmVxdWVzdC5zZW5kKHN0cmluZ2lmeShvcHRzLmRhdGEpKTtcbiAgfSxcblxuICBfbG9nRGVidWc6IGZ1bmN0aW9uKGxldmVsKSB7XG4gICAgaWYgKHRoaXMuX29yaWdpbmFsQ29uc29sZU1ldGhvZHNbbGV2ZWxdICYmIHRoaXMuZGVidWcpIHtcbiAgICAgIC8vIEluIElFPDEwIGNvbnNvbGUgbWV0aG9kcyBkbyBub3QgaGF2ZSB0aGVpciBvd24gJ2FwcGx5JyBtZXRob2RcbiAgICAgIEZ1bmN0aW9uLnByb3RvdHlwZS5hcHBseS5jYWxsKFxuICAgICAgICB0aGlzLl9vcmlnaW5hbENvbnNvbGVNZXRob2RzW2xldmVsXSxcbiAgICAgICAgdGhpcy5fb3JpZ2luYWxDb25zb2xlLFxuICAgICAgICBbXS5zbGljZS5jYWxsKGFyZ3VtZW50cywgMSlcbiAgICAgICk7XG4gICAgfVxuICB9LFxuXG4gIF9tZXJnZUNvbnRleHQ6IGZ1bmN0aW9uKGtleSwgY29udGV4dCkge1xuICAgIGlmIChpc1VuZGVmaW5lZChjb250ZXh0KSkge1xuICAgICAgZGVsZXRlIHRoaXMuX2dsb2JhbENvbnRleHRba2V5XTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5fZ2xvYmFsQ29udGV4dFtrZXldID0gb2JqZWN0TWVyZ2UodGhpcy5fZ2xvYmFsQ29udGV4dFtrZXldIHx8IHt9LCBjb250ZXh0KTtcbiAgICB9XG4gIH1cbn07XG5cbi8vIERlcHJlY2F0aW9uc1xuUmF2ZW4ucHJvdG90eXBlLnNldFVzZXIgPSBSYXZlbi5wcm90b3R5cGUuc2V0VXNlckNvbnRleHQ7XG5SYXZlbi5wcm90b3R5cGUuc2V0UmVsZWFzZUNvbnRleHQgPSBSYXZlbi5wcm90b3R5cGUuc2V0UmVsZWFzZTtcblxubW9kdWxlLmV4cG9ydHMgPSBSYXZlbjtcbiIsIi8qKlxuICogRW5mb3JjZXMgYSBzaW5nbGUgaW5zdGFuY2Ugb2YgdGhlIFJhdmVuIGNsaWVudCwgYW5kIHRoZVxuICogbWFpbiBlbnRyeSBwb2ludCBmb3IgUmF2ZW4uIElmIHlvdSBhcmUgYSBjb25zdW1lciBvZiB0aGVcbiAqIFJhdmVuIGxpYnJhcnksIHlvdSBTSE9VTEQgbG9hZCB0aGlzIGZpbGUgKHZzIHJhdmVuLmpzKS5cbiAqKi9cblxudmFyIFJhdmVuQ29uc3RydWN0b3IgPSByZXF1aXJlKCcuL3JhdmVuJyk7XG5cbi8vIFRoaXMgaXMgdG8gYmUgZGVmZW5zaXZlIGluIGVudmlyb25tZW50cyB3aGVyZSB3aW5kb3cgZG9lcyBub3QgZXhpc3QgKHNlZSBodHRwczovL2dpdGh1Yi5jb20vZ2V0c2VudHJ5L3JhdmVuLWpzL3B1bGwvNzg1KVxudmFyIF93aW5kb3cgPVxuICB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJ1xuICAgID8gd2luZG93XG4gICAgOiB0eXBlb2YgZ2xvYmFsICE9PSAndW5kZWZpbmVkJyA/IGdsb2JhbCA6IHR5cGVvZiBzZWxmICE9PSAndW5kZWZpbmVkJyA/IHNlbGYgOiB7fTtcbnZhciBfUmF2ZW4gPSBfd2luZG93LlJhdmVuO1xuXG52YXIgUmF2ZW4gPSBuZXcgUmF2ZW5Db25zdHJ1Y3RvcigpO1xuXG4vKlxuICogQWxsb3cgbXVsdGlwbGUgdmVyc2lvbnMgb2YgUmF2ZW4gdG8gYmUgaW5zdGFsbGVkLlxuICogU3RyaXAgUmF2ZW4gZnJvbSB0aGUgZ2xvYmFsIGNvbnRleHQgYW5kIHJldHVybnMgdGhlIGluc3RhbmNlLlxuICpcbiAqIEByZXR1cm4ge1JhdmVufVxuICovXG5SYXZlbi5ub0NvbmZsaWN0ID0gZnVuY3Rpb24oKSB7XG4gIF93aW5kb3cuUmF2ZW4gPSBfUmF2ZW47XG4gIHJldHVybiBSYXZlbjtcbn07XG5cblJhdmVuLmFmdGVyTG9hZCgpO1xuXG5tb2R1bGUuZXhwb3J0cyA9IFJhdmVuO1xuIiwidmFyIF93aW5kb3cgPVxuICB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJ1xuICAgID8gd2luZG93XG4gICAgOiB0eXBlb2YgZ2xvYmFsICE9PSAndW5kZWZpbmVkJyA/IGdsb2JhbCA6IHR5cGVvZiBzZWxmICE9PSAndW5kZWZpbmVkJyA/IHNlbGYgOiB7fTtcblxuZnVuY3Rpb24gaXNPYmplY3Qod2hhdCkge1xuICByZXR1cm4gdHlwZW9mIHdoYXQgPT09ICdvYmplY3QnICYmIHdoYXQgIT09IG51bGw7XG59XG5cbi8vIFlhbmtlZCBmcm9tIGh0dHBzOi8vZ2l0LmlvL3ZTOERWIHJlLXVzZWQgdW5kZXIgQ0MwXG4vLyB3aXRoIHNvbWUgdGlueSBtb2RpZmljYXRpb25zXG5mdW5jdGlvbiBpc0Vycm9yKHZhbHVlKSB7XG4gIHN3aXRjaCAoe30udG9TdHJpbmcuY2FsbCh2YWx1ZSkpIHtcbiAgICBjYXNlICdbb2JqZWN0IEVycm9yXSc6XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICBjYXNlICdbb2JqZWN0IEV4Y2VwdGlvbl0nOlxuICAgICAgcmV0dXJuIHRydWU7XG4gICAgY2FzZSAnW29iamVjdCBET01FeGNlcHRpb25dJzpcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIGRlZmF1bHQ6XG4gICAgICByZXR1cm4gdmFsdWUgaW5zdGFuY2VvZiBFcnJvcjtcbiAgfVxufVxuXG5mdW5jdGlvbiBpc0Vycm9yRXZlbnQodmFsdWUpIHtcbiAgcmV0dXJuIHN1cHBvcnRzRXJyb3JFdmVudCgpICYmIHt9LnRvU3RyaW5nLmNhbGwodmFsdWUpID09PSAnW29iamVjdCBFcnJvckV2ZW50XSc7XG59XG5cbmZ1bmN0aW9uIGlzVW5kZWZpbmVkKHdoYXQpIHtcbiAgcmV0dXJuIHdoYXQgPT09IHZvaWQgMDtcbn1cblxuZnVuY3Rpb24gaXNGdW5jdGlvbih3aGF0KSB7XG4gIHJldHVybiB0eXBlb2Ygd2hhdCA9PT0gJ2Z1bmN0aW9uJztcbn1cblxuZnVuY3Rpb24gaXNTdHJpbmcod2hhdCkge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHdoYXQpID09PSAnW29iamVjdCBTdHJpbmddJztcbn1cblxuZnVuY3Rpb24gaXNBcnJheSh3aGF0KSB7XG4gIHJldHVybiBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwod2hhdCkgPT09ICdbb2JqZWN0IEFycmF5XSc7XG59XG5cbmZ1bmN0aW9uIGlzRW1wdHlPYmplY3Qod2hhdCkge1xuICBmb3IgKHZhciBfIGluIHdoYXQpIHtcbiAgICBpZiAod2hhdC5oYXNPd25Qcm9wZXJ0eShfKSkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgfVxuICByZXR1cm4gdHJ1ZTtcbn1cblxuZnVuY3Rpb24gc3VwcG9ydHNFcnJvckV2ZW50KCkge1xuICB0cnkge1xuICAgIG5ldyBFcnJvckV2ZW50KCcnKTsgLy8gZXNsaW50LWRpc2FibGUtbGluZSBuby1uZXdcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxufVxuXG5mdW5jdGlvbiB3cmFwcGVkQ2FsbGJhY2soY2FsbGJhY2spIHtcbiAgZnVuY3Rpb24gZGF0YUNhbGxiYWNrKGRhdGEsIG9yaWdpbmFsKSB7XG4gICAgdmFyIG5vcm1hbGl6ZWREYXRhID0gY2FsbGJhY2soZGF0YSkgfHwgZGF0YTtcbiAgICBpZiAob3JpZ2luYWwpIHtcbiAgICAgIHJldHVybiBvcmlnaW5hbChub3JtYWxpemVkRGF0YSkgfHwgbm9ybWFsaXplZERhdGE7XG4gICAgfVxuICAgIHJldHVybiBub3JtYWxpemVkRGF0YTtcbiAgfVxuXG4gIHJldHVybiBkYXRhQ2FsbGJhY2s7XG59XG5cbmZ1bmN0aW9uIGVhY2gob2JqLCBjYWxsYmFjaykge1xuICB2YXIgaSwgajtcblxuICBpZiAoaXNVbmRlZmluZWQob2JqLmxlbmd0aCkpIHtcbiAgICBmb3IgKGkgaW4gb2JqKSB7XG4gICAgICBpZiAoaGFzS2V5KG9iaiwgaSkpIHtcbiAgICAgICAgY2FsbGJhY2suY2FsbChudWxsLCBpLCBvYmpbaV0pO1xuICAgICAgfVxuICAgIH1cbiAgfSBlbHNlIHtcbiAgICBqID0gb2JqLmxlbmd0aDtcbiAgICBpZiAoaikge1xuICAgICAgZm9yIChpID0gMDsgaSA8IGo7IGkrKykge1xuICAgICAgICBjYWxsYmFjay5jYWxsKG51bGwsIGksIG9ialtpXSk7XG4gICAgICB9XG4gICAgfVxuICB9XG59XG5cbmZ1bmN0aW9uIG9iamVjdE1lcmdlKG9iajEsIG9iajIpIHtcbiAgaWYgKCFvYmoyKSB7XG4gICAgcmV0dXJuIG9iajE7XG4gIH1cbiAgZWFjaChvYmoyLCBmdW5jdGlvbihrZXksIHZhbHVlKSB7XG4gICAgb2JqMVtrZXldID0gdmFsdWU7XG4gIH0pO1xuICByZXR1cm4gb2JqMTtcbn1cblxuLyoqXG4gKiBUaGlzIGZ1bmN0aW9uIGlzIG9ubHkgdXNlZCBmb3IgcmVhY3QtbmF0aXZlLlxuICogcmVhY3QtbmF0aXZlIGZyZWV6ZXMgb2JqZWN0IHRoYXQgaGF2ZSBhbHJlYWR5IGJlZW4gc2VudCBvdmVyIHRoZVxuICoganMgYnJpZGdlLiBXZSBuZWVkIHRoaXMgZnVuY3Rpb24gaW4gb3JkZXIgdG8gY2hlY2sgaWYgdGhlIG9iamVjdCBpcyBmcm96ZW4uXG4gKiBTbyBpdCdzIG9rIHRoYXQgb2JqZWN0RnJvemVuIHJldHVybnMgZmFsc2UgaWYgT2JqZWN0LmlzRnJvemVuIGlzIG5vdFxuICogc3VwcG9ydGVkIGJlY2F1c2UgaXQncyBub3QgcmVsZXZhbnQgZm9yIG90aGVyIFwicGxhdGZvcm1zXCIuIFNlZSByZWxhdGVkIGlzc3VlOlxuICogaHR0cHM6Ly9naXRodWIuY29tL2dldHNlbnRyeS9yZWFjdC1uYXRpdmUtc2VudHJ5L2lzc3Vlcy81N1xuICovXG5mdW5jdGlvbiBvYmplY3RGcm96ZW4ob2JqKSB7XG4gIGlmICghT2JqZWN0LmlzRnJvemVuKSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG4gIHJldHVybiBPYmplY3QuaXNGcm96ZW4ob2JqKTtcbn1cblxuZnVuY3Rpb24gdHJ1bmNhdGUoc3RyLCBtYXgpIHtcbiAgcmV0dXJuICFtYXggfHwgc3RyLmxlbmd0aCA8PSBtYXggPyBzdHIgOiBzdHIuc3Vic3RyKDAsIG1heCkgKyAnXFx1MjAyNic7XG59XG5cbi8qKlxuICogaGFzS2V5LCBhIGJldHRlciBmb3JtIG9mIGhhc093blByb3BlcnR5XG4gKiBFeGFtcGxlOiBoYXNLZXkoTWFpbkhvc3RPYmplY3QsIHByb3BlcnR5KSA9PT0gdHJ1ZS9mYWxzZVxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBob3N0IG9iamVjdCB0byBjaGVjayBwcm9wZXJ0eVxuICogQHBhcmFtIHtzdHJpbmd9IGtleSB0byBjaGVja1xuICovXG5mdW5jdGlvbiBoYXNLZXkob2JqZWN0LCBrZXkpIHtcbiAgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmplY3QsIGtleSk7XG59XG5cbmZ1bmN0aW9uIGpvaW5SZWdFeHAocGF0dGVybnMpIHtcbiAgLy8gQ29tYmluZSBhbiBhcnJheSBvZiByZWd1bGFyIGV4cHJlc3Npb25zIGFuZCBzdHJpbmdzIGludG8gb25lIGxhcmdlIHJlZ2V4cFxuICAvLyBCZSBtYWQuXG4gIHZhciBzb3VyY2VzID0gW10sXG4gICAgaSA9IDAsXG4gICAgbGVuID0gcGF0dGVybnMubGVuZ3RoLFxuICAgIHBhdHRlcm47XG5cbiAgZm9yICg7IGkgPCBsZW47IGkrKykge1xuICAgIHBhdHRlcm4gPSBwYXR0ZXJuc1tpXTtcbiAgICBpZiAoaXNTdHJpbmcocGF0dGVybikpIHtcbiAgICAgIC8vIElmIGl0J3MgYSBzdHJpbmcsIHdlIG5lZWQgdG8gZXNjYXBlIGl0XG4gICAgICAvLyBUYWtlbiBmcm9tOiBodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9KYXZhU2NyaXB0L0d1aWRlL1JlZ3VsYXJfRXhwcmVzc2lvbnNcbiAgICAgIHNvdXJjZXMucHVzaChwYXR0ZXJuLnJlcGxhY2UoLyhbLiorP149IToke30oKXxcXFtcXF1cXC9cXFxcXSkvZywgJ1xcXFwkMScpKTtcbiAgICB9IGVsc2UgaWYgKHBhdHRlcm4gJiYgcGF0dGVybi5zb3VyY2UpIHtcbiAgICAgIC8vIElmIGl0J3MgYSByZWdleHAgYWxyZWFkeSwgd2Ugd2FudCB0byBleHRyYWN0IHRoZSBzb3VyY2VcbiAgICAgIHNvdXJjZXMucHVzaChwYXR0ZXJuLnNvdXJjZSk7XG4gICAgfVxuICAgIC8vIEludGVudGlvbmFsbHkgc2tpcCBvdGhlciBjYXNlc1xuICB9XG4gIHJldHVybiBuZXcgUmVnRXhwKHNvdXJjZXMuam9pbignfCcpLCAnaScpO1xufVxuXG5mdW5jdGlvbiB1cmxlbmNvZGUobykge1xuICB2YXIgcGFpcnMgPSBbXTtcbiAgZWFjaChvLCBmdW5jdGlvbihrZXksIHZhbHVlKSB7XG4gICAgcGFpcnMucHVzaChlbmNvZGVVUklDb21wb25lbnQoa2V5KSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudCh2YWx1ZSkpO1xuICB9KTtcbiAgcmV0dXJuIHBhaXJzLmpvaW4oJyYnKTtcbn1cblxuLy8gYm9ycm93ZWQgZnJvbSBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjMzk4NiNhcHBlbmRpeC1CXG4vLyBpbnRlbnRpb25hbGx5IHVzaW5nIHJlZ2V4IGFuZCBub3QgPGEvPiBocmVmIHBhcnNpbmcgdHJpY2sgYmVjYXVzZSBSZWFjdCBOYXRpdmUgYW5kIG90aGVyXG4vLyBlbnZpcm9ubWVudHMgd2hlcmUgRE9NIG1pZ2h0IG5vdCBiZSBhdmFpbGFibGVcbmZ1bmN0aW9uIHBhcnNlVXJsKHVybCkge1xuICB2YXIgbWF0Y2ggPSB1cmwubWF0Y2goL14oKFteOlxcLz8jXSspOik/KFxcL1xcLyhbXlxcLz8jXSopKT8oW14/I10qKShcXD8oW14jXSopKT8oIyguKikpPyQvKTtcbiAgaWYgKCFtYXRjaCkgcmV0dXJuIHt9O1xuXG4gIC8vIGNvZXJjZSB0byB1bmRlZmluZWQgdmFsdWVzIHRvIGVtcHR5IHN0cmluZyBzbyB3ZSBkb24ndCBnZXQgJ3VuZGVmaW5lZCdcbiAgdmFyIHF1ZXJ5ID0gbWF0Y2hbNl0gfHwgJyc7XG4gIHZhciBmcmFnbWVudCA9IG1hdGNoWzhdIHx8ICcnO1xuICByZXR1cm4ge1xuICAgIHByb3RvY29sOiBtYXRjaFsyXSxcbiAgICBob3N0OiBtYXRjaFs0XSxcbiAgICBwYXRoOiBtYXRjaFs1XSxcbiAgICByZWxhdGl2ZTogbWF0Y2hbNV0gKyBxdWVyeSArIGZyYWdtZW50IC8vIGV2ZXJ5dGhpbmcgbWludXMgb3JpZ2luXG4gIH07XG59XG5mdW5jdGlvbiB1dWlkNCgpIHtcbiAgdmFyIGNyeXB0byA9IF93aW5kb3cuY3J5cHRvIHx8IF93aW5kb3cubXNDcnlwdG87XG5cbiAgaWYgKCFpc1VuZGVmaW5lZChjcnlwdG8pICYmIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMpIHtcbiAgICAvLyBVc2Ugd2luZG93LmNyeXB0byBBUEkgaWYgYXZhaWxhYmxlXG4gICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLXVuZGVmXG4gICAgdmFyIGFyciA9IG5ldyBVaW50MTZBcnJheSg4KTtcbiAgICBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKGFycik7XG5cbiAgICAvLyBzZXQgNCBpbiBieXRlIDdcbiAgICBhcnJbM10gPSAoYXJyWzNdICYgMHhmZmYpIHwgMHg0MDAwO1xuICAgIC8vIHNldCAyIG1vc3Qgc2lnbmlmaWNhbnQgYml0cyBvZiBieXRlIDkgdG8gJzEwJ1xuICAgIGFycls0XSA9IChhcnJbNF0gJiAweDNmZmYpIHwgMHg4MDAwO1xuXG4gICAgdmFyIHBhZCA9IGZ1bmN0aW9uKG51bSkge1xuICAgICAgdmFyIHYgPSBudW0udG9TdHJpbmcoMTYpO1xuICAgICAgd2hpbGUgKHYubGVuZ3RoIDwgNCkge1xuICAgICAgICB2ID0gJzAnICsgdjtcbiAgICAgIH1cbiAgICAgIHJldHVybiB2O1xuICAgIH07XG5cbiAgICByZXR1cm4gKFxuICAgICAgcGFkKGFyclswXSkgK1xuICAgICAgcGFkKGFyclsxXSkgK1xuICAgICAgcGFkKGFyclsyXSkgK1xuICAgICAgcGFkKGFyclszXSkgK1xuICAgICAgcGFkKGFycls0XSkgK1xuICAgICAgcGFkKGFycls1XSkgK1xuICAgICAgcGFkKGFycls2XSkgK1xuICAgICAgcGFkKGFycls3XSlcbiAgICApO1xuICB9IGVsc2Uge1xuICAgIC8vIGh0dHA6Ly9zdGFja292ZXJmbG93LmNvbS9xdWVzdGlvbnMvMTA1MDM0L2hvdy10by1jcmVhdGUtYS1ndWlkLXV1aWQtaW4tamF2YXNjcmlwdC8yMTE3NTIzIzIxMTc1MjNcbiAgICByZXR1cm4gJ3h4eHh4eHh4eHh4eDR4eHh5eHh4eHh4eHh4eHh4eHh4Jy5yZXBsYWNlKC9beHldL2csIGZ1bmN0aW9uKGMpIHtcbiAgICAgIHZhciByID0gKE1hdGgucmFuZG9tKCkgKiAxNikgfCAwLFxuICAgICAgICB2ID0gYyA9PT0gJ3gnID8gciA6IChyICYgMHgzKSB8IDB4ODtcbiAgICAgIHJldHVybiB2LnRvU3RyaW5nKDE2KTtcbiAgICB9KTtcbiAgfVxufVxuXG4vKipcbiAqIEdpdmVuIGEgY2hpbGQgRE9NIGVsZW1lbnQsIHJldHVybnMgYSBxdWVyeS1zZWxlY3RvciBzdGF0ZW1lbnQgZGVzY3JpYmluZyB0aGF0XG4gKiBhbmQgaXRzIGFuY2VzdG9yc1xuICogZS5nLiBbSFRNTEVsZW1lbnRdID0+IGJvZHkgPiBkaXYgPiBpbnB1dCNmb28uYnRuW25hbWU9YmF6XVxuICogQHBhcmFtIGVsZW1cbiAqIEByZXR1cm5zIHtzdHJpbmd9XG4gKi9cbmZ1bmN0aW9uIGh0bWxUcmVlQXNTdHJpbmcoZWxlbSkge1xuICAvKiBlc2xpbnQgbm8tZXh0cmEtcGFyZW5zOjAqL1xuICB2YXIgTUFYX1RSQVZFUlNFX0hFSUdIVCA9IDUsXG4gICAgTUFYX09VVFBVVF9MRU4gPSA4MCxcbiAgICBvdXQgPSBbXSxcbiAgICBoZWlnaHQgPSAwLFxuICAgIGxlbiA9IDAsXG4gICAgc2VwYXJhdG9yID0gJyA+ICcsXG4gICAgc2VwTGVuZ3RoID0gc2VwYXJhdG9yLmxlbmd0aCxcbiAgICBuZXh0U3RyO1xuXG4gIHdoaWxlIChlbGVtICYmIGhlaWdodCsrIDwgTUFYX1RSQVZFUlNFX0hFSUdIVCkge1xuICAgIG5leHRTdHIgPSBodG1sRWxlbWVudEFzU3RyaW5nKGVsZW0pO1xuICAgIC8vIGJhaWwgb3V0IGlmXG4gICAgLy8gLSBuZXh0U3RyIGlzIHRoZSAnaHRtbCcgZWxlbWVudFxuICAgIC8vIC0gdGhlIGxlbmd0aCBvZiB0aGUgc3RyaW5nIHRoYXQgd291bGQgYmUgY3JlYXRlZCBleGNlZWRzIE1BWF9PVVRQVVRfTEVOXG4gICAgLy8gICAoaWdub3JlIHRoaXMgbGltaXQgaWYgd2UgYXJlIG9uIHRoZSBmaXJzdCBpdGVyYXRpb24pXG4gICAgaWYgKFxuICAgICAgbmV4dFN0ciA9PT0gJ2h0bWwnIHx8XG4gICAgICAoaGVpZ2h0ID4gMSAmJiBsZW4gKyBvdXQubGVuZ3RoICogc2VwTGVuZ3RoICsgbmV4dFN0ci5sZW5ndGggPj0gTUFYX09VVFBVVF9MRU4pXG4gICAgKSB7XG4gICAgICBicmVhaztcbiAgICB9XG5cbiAgICBvdXQucHVzaChuZXh0U3RyKTtcblxuICAgIGxlbiArPSBuZXh0U3RyLmxlbmd0aDtcbiAgICBlbGVtID0gZWxlbS5wYXJlbnROb2RlO1xuICB9XG5cbiAgcmV0dXJuIG91dC5yZXZlcnNlKCkuam9pbihzZXBhcmF0b3IpO1xufVxuXG4vKipcbiAqIFJldHVybnMgYSBzaW1wbGUsIHF1ZXJ5LXNlbGVjdG9yIHJlcHJlc2VudGF0aW9uIG9mIGEgRE9NIGVsZW1lbnRcbiAqIGUuZy4gW0hUTUxFbGVtZW50XSA9PiBpbnB1dCNmb28uYnRuW25hbWU9YmF6XVxuICogQHBhcmFtIEhUTUxFbGVtZW50XG4gKiBAcmV0dXJucyB7c3RyaW5nfVxuICovXG5mdW5jdGlvbiBodG1sRWxlbWVudEFzU3RyaW5nKGVsZW0pIHtcbiAgdmFyIG91dCA9IFtdLFxuICAgIGNsYXNzTmFtZSxcbiAgICBjbGFzc2VzLFxuICAgIGtleSxcbiAgICBhdHRyLFxuICAgIGk7XG5cbiAgaWYgKCFlbGVtIHx8ICFlbGVtLnRhZ05hbWUpIHtcbiAgICByZXR1cm4gJyc7XG4gIH1cblxuICBvdXQucHVzaChlbGVtLnRhZ05hbWUudG9Mb3dlckNhc2UoKSk7XG4gIGlmIChlbGVtLmlkKSB7XG4gICAgb3V0LnB1c2goJyMnICsgZWxlbS5pZCk7XG4gIH1cblxuICBjbGFzc05hbWUgPSBlbGVtLmNsYXNzTmFtZTtcbiAgaWYgKGNsYXNzTmFtZSAmJiBpc1N0cmluZyhjbGFzc05hbWUpKSB7XG4gICAgY2xhc3NlcyA9IGNsYXNzTmFtZS5zcGxpdCgvXFxzKy8pO1xuICAgIGZvciAoaSA9IDA7IGkgPCBjbGFzc2VzLmxlbmd0aDsgaSsrKSB7XG4gICAgICBvdXQucHVzaCgnLicgKyBjbGFzc2VzW2ldKTtcbiAgICB9XG4gIH1cbiAgdmFyIGF0dHJXaGl0ZWxpc3QgPSBbJ3R5cGUnLCAnbmFtZScsICd0aXRsZScsICdhbHQnXTtcbiAgZm9yIChpID0gMDsgaSA8IGF0dHJXaGl0ZWxpc3QubGVuZ3RoOyBpKyspIHtcbiAgICBrZXkgPSBhdHRyV2hpdGVsaXN0W2ldO1xuICAgIGF0dHIgPSBlbGVtLmdldEF0dHJpYnV0ZShrZXkpO1xuICAgIGlmIChhdHRyKSB7XG4gICAgICBvdXQucHVzaCgnWycgKyBrZXkgKyAnPVwiJyArIGF0dHIgKyAnXCJdJyk7XG4gICAgfVxuICB9XG4gIHJldHVybiBvdXQuam9pbignJyk7XG59XG5cbi8qKlxuICogUmV0dXJucyB0cnVlIGlmIGVpdGhlciBhIE9SIGIgaXMgdHJ1dGh5LCBidXQgbm90IGJvdGhcbiAqL1xuZnVuY3Rpb24gaXNPbmx5T25lVHJ1dGh5KGEsIGIpIHtcbiAgcmV0dXJuICEhKCEhYSBeICEhYik7XG59XG5cbi8qKlxuICogUmV0dXJucyB0cnVlIGlmIHRoZSB0d28gaW5wdXQgZXhjZXB0aW9uIGludGVyZmFjZXMgaGF2ZSB0aGUgc2FtZSBjb250ZW50XG4gKi9cbmZ1bmN0aW9uIGlzU2FtZUV4Y2VwdGlvbihleDEsIGV4Mikge1xuICBpZiAoaXNPbmx5T25lVHJ1dGh5KGV4MSwgZXgyKSkgcmV0dXJuIGZhbHNlO1xuXG4gIGV4MSA9IGV4MS52YWx1ZXNbMF07XG4gIGV4MiA9IGV4Mi52YWx1ZXNbMF07XG5cbiAgaWYgKGV4MS50eXBlICE9PSBleDIudHlwZSB8fCBleDEudmFsdWUgIT09IGV4Mi52YWx1ZSkgcmV0dXJuIGZhbHNlO1xuXG4gIHJldHVybiBpc1NhbWVTdGFja3RyYWNlKGV4MS5zdGFja3RyYWNlLCBleDIuc3RhY2t0cmFjZSk7XG59XG5cbi8qKlxuICogUmV0dXJucyB0cnVlIGlmIHRoZSB0d28gaW5wdXQgc3RhY2sgdHJhY2UgaW50ZXJmYWNlcyBoYXZlIHRoZSBzYW1lIGNvbnRlbnRcbiAqL1xuZnVuY3Rpb24gaXNTYW1lU3RhY2t0cmFjZShzdGFjazEsIHN0YWNrMikge1xuICBpZiAoaXNPbmx5T25lVHJ1dGh5KHN0YWNrMSwgc3RhY2syKSkgcmV0dXJuIGZhbHNlO1xuXG4gIHZhciBmcmFtZXMxID0gc3RhY2sxLmZyYW1lcztcbiAgdmFyIGZyYW1lczIgPSBzdGFjazIuZnJhbWVzO1xuXG4gIC8vIEV4aXQgZWFybHkgaWYgZnJhbWUgY291bnQgZGlmZmVyc1xuICBpZiAoZnJhbWVzMS5sZW5ndGggIT09IGZyYW1lczIubGVuZ3RoKSByZXR1cm4gZmFsc2U7XG5cbiAgLy8gSXRlcmF0ZSB0aHJvdWdoIGV2ZXJ5IGZyYW1lOyBiYWlsIG91dCBpZiBhbnl0aGluZyBkaWZmZXJzXG4gIHZhciBhLCBiO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IGZyYW1lczEubGVuZ3RoOyBpKyspIHtcbiAgICBhID0gZnJhbWVzMVtpXTtcbiAgICBiID0gZnJhbWVzMltpXTtcbiAgICBpZiAoXG4gICAgICBhLmZpbGVuYW1lICE9PSBiLmZpbGVuYW1lIHx8XG4gICAgICBhLmxpbmVubyAhPT0gYi5saW5lbm8gfHxcbiAgICAgIGEuY29sbm8gIT09IGIuY29sbm8gfHxcbiAgICAgIGFbJ2Z1bmN0aW9uJ10gIT09IGJbJ2Z1bmN0aW9uJ11cbiAgICApXG4gICAgICByZXR1cm4gZmFsc2U7XG4gIH1cbiAgcmV0dXJuIHRydWU7XG59XG5cbi8qKlxuICogUG9seWZpbGwgYSBtZXRob2RcbiAqIEBwYXJhbSBvYmogb2JqZWN0IGUuZy4gYGRvY3VtZW50YFxuICogQHBhcmFtIG5hbWUgbWV0aG9kIG5hbWUgcHJlc2VudCBvbiBvYmplY3QgZS5nLiBgYWRkRXZlbnRMaXN0ZW5lcmBcbiAqIEBwYXJhbSByZXBsYWNlbWVudCByZXBsYWNlbWVudCBmdW5jdGlvblxuICogQHBhcmFtIHRyYWNrIHtvcHRpb25hbH0gcmVjb3JkIGluc3RydW1lbnRhdGlvbiB0byBhbiBhcnJheVxuICovXG5mdW5jdGlvbiBmaWxsKG9iaiwgbmFtZSwgcmVwbGFjZW1lbnQsIHRyYWNrKSB7XG4gIHZhciBvcmlnID0gb2JqW25hbWVdO1xuICBvYmpbbmFtZV0gPSByZXBsYWNlbWVudChvcmlnKTtcbiAgb2JqW25hbWVdLl9fcmF2ZW5fXyA9IHRydWU7XG4gIG9ialtuYW1lXS5fX29yaWdfXyA9IG9yaWc7XG4gIGlmICh0cmFjaykge1xuICAgIHRyYWNrLnB1c2goW29iaiwgbmFtZSwgb3JpZ10pO1xuICB9XG59XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICBpc09iamVjdDogaXNPYmplY3QsXG4gIGlzRXJyb3I6IGlzRXJyb3IsXG4gIGlzRXJyb3JFdmVudDogaXNFcnJvckV2ZW50LFxuICBpc1VuZGVmaW5lZDogaXNVbmRlZmluZWQsXG4gIGlzRnVuY3Rpb246IGlzRnVuY3Rpb24sXG4gIGlzU3RyaW5nOiBpc1N0cmluZyxcbiAgaXNBcnJheTogaXNBcnJheSxcbiAgaXNFbXB0eU9iamVjdDogaXNFbXB0eU9iamVjdCxcbiAgc3VwcG9ydHNFcnJvckV2ZW50OiBzdXBwb3J0c0Vycm9yRXZlbnQsXG4gIHdyYXBwZWRDYWxsYmFjazogd3JhcHBlZENhbGxiYWNrLFxuICBlYWNoOiBlYWNoLFxuICBvYmplY3RNZXJnZTogb2JqZWN0TWVyZ2UsXG4gIHRydW5jYXRlOiB0cnVuY2F0ZSxcbiAgb2JqZWN0RnJvemVuOiBvYmplY3RGcm96ZW4sXG4gIGhhc0tleTogaGFzS2V5LFxuICBqb2luUmVnRXhwOiBqb2luUmVnRXhwLFxuICB1cmxlbmNvZGU6IHVybGVuY29kZSxcbiAgdXVpZDQ6IHV1aWQ0LFxuICBodG1sVHJlZUFzU3RyaW5nOiBodG1sVHJlZUFzU3RyaW5nLFxuICBodG1sRWxlbWVudEFzU3RyaW5nOiBodG1sRWxlbWVudEFzU3RyaW5nLFxuICBpc1NhbWVFeGNlcHRpb246IGlzU2FtZUV4Y2VwdGlvbixcbiAgaXNTYW1lU3RhY2t0cmFjZTogaXNTYW1lU3RhY2t0cmFjZSxcbiAgcGFyc2VVcmw6IHBhcnNlVXJsLFxuICBmaWxsOiBmaWxsXG59O1xuIiwidmFyIHV0aWxzID0gcmVxdWlyZSgnLi4vLi4vc3JjL3V0aWxzJyk7XG5cbi8qXG4gVHJhY2VLaXQgLSBDcm9zcyBicm93ZXIgc3RhY2sgdHJhY2VzXG5cbiBUaGlzIHdhcyBvcmlnaW5hbGx5IGZvcmtlZCBmcm9tIGdpdGh1Yi5jb20vb2NjL1RyYWNlS2l0LCBidXQgaGFzIHNpbmNlIGJlZW5cbiBsYXJnZWx5IHJlLXdyaXR0ZW4gYW5kIGlzIG5vdyBtYWludGFpbmVkIGFzIHBhcnQgb2YgcmF2ZW4tanMuICBUZXN0cyBmb3JcbiB0aGlzIGFyZSBpbiB0ZXN0L3ZlbmRvci5cblxuIE1JVCBsaWNlbnNlXG4qL1xuXG52YXIgVHJhY2VLaXQgPSB7XG4gIGNvbGxlY3RXaW5kb3dFcnJvcnM6IHRydWUsXG4gIGRlYnVnOiBmYWxzZVxufTtcblxuLy8gVGhpcyBpcyB0byBiZSBkZWZlbnNpdmUgaW4gZW52aXJvbm1lbnRzIHdoZXJlIHdpbmRvdyBkb2VzIG5vdCBleGlzdCAoc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9nZXRzZW50cnkvcmF2ZW4tanMvcHVsbC83ODUpXG52YXIgX3dpbmRvdyA9XG4gIHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnXG4gICAgPyB3aW5kb3dcbiAgICA6IHR5cGVvZiBnbG9iYWwgIT09ICd1bmRlZmluZWQnID8gZ2xvYmFsIDogdHlwZW9mIHNlbGYgIT09ICd1bmRlZmluZWQnID8gc2VsZiA6IHt9O1xuXG4vLyBnbG9iYWwgcmVmZXJlbmNlIHRvIHNsaWNlXG52YXIgX3NsaWNlID0gW10uc2xpY2U7XG52YXIgVU5LTk9XTl9GVU5DVElPTiA9ICc/JztcblxuLy8gaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvSmF2YVNjcmlwdC9SZWZlcmVuY2UvR2xvYmFsX09iamVjdHMvRXJyb3IjRXJyb3JfdHlwZXNcbnZhciBFUlJPUl9UWVBFU19SRSA9IC9eKD86W1V1XW5jYXVnaHQgKD86ZXhjZXB0aW9uOiApPyk/KD86KCg/OkV2YWx8SW50ZXJuYWx8UmFuZ2V8UmVmZXJlbmNlfFN5bnRheHxUeXBlfFVSSXwpRXJyb3IpOiApPyguKikkLztcblxuZnVuY3Rpb24gZ2V0TG9jYXRpb25IcmVmKCkge1xuICBpZiAodHlwZW9mIGRvY3VtZW50ID09PSAndW5kZWZpbmVkJyB8fCBkb2N1bWVudC5sb2NhdGlvbiA9PSBudWxsKSByZXR1cm4gJyc7XG5cbiAgcmV0dXJuIGRvY3VtZW50LmxvY2F0aW9uLmhyZWY7XG59XG5cbi8qKlxuICogVHJhY2VLaXQucmVwb3J0OiBjcm9zcy1icm93c2VyIHByb2Nlc3Npbmcgb2YgdW5oYW5kbGVkIGV4Y2VwdGlvbnNcbiAqXG4gKiBTeW50YXg6XG4gKiAgIFRyYWNlS2l0LnJlcG9ydC5zdWJzY3JpYmUoZnVuY3Rpb24oc3RhY2tJbmZvKSB7IC4uLiB9KVxuICogICBUcmFjZUtpdC5yZXBvcnQudW5zdWJzY3JpYmUoZnVuY3Rpb24oc3RhY2tJbmZvKSB7IC4uLiB9KVxuICogICBUcmFjZUtpdC5yZXBvcnQoZXhjZXB0aW9uKVxuICogICB0cnkgeyAuLi5jb2RlLi4uIH0gY2F0Y2goZXgpIHsgVHJhY2VLaXQucmVwb3J0KGV4KTsgfVxuICpcbiAqIFN1cHBvcnRzOlxuICogICAtIEZpcmVmb3g6IGZ1bGwgc3RhY2sgdHJhY2Ugd2l0aCBsaW5lIG51bWJlcnMsIHBsdXMgY29sdW1uIG51bWJlclxuICogICAgICAgICAgICAgIG9uIHRvcCBmcmFtZTsgY29sdW1uIG51bWJlciBpcyBub3QgZ3VhcmFudGVlZFxuICogICAtIE9wZXJhOiAgIGZ1bGwgc3RhY2sgdHJhY2Ugd2l0aCBsaW5lIGFuZCBjb2x1bW4gbnVtYmVyc1xuICogICAtIENocm9tZTogIGZ1bGwgc3RhY2sgdHJhY2Ugd2l0aCBsaW5lIGFuZCBjb2x1bW4gbnVtYmVyc1xuICogICAtIFNhZmFyaTogIGxpbmUgYW5kIGNvbHVtbiBudW1iZXIgZm9yIHRoZSB0b3AgZnJhbWUgb25seTsgc29tZSBmcmFtZXNcbiAqICAgICAgICAgICAgICBtYXkgYmUgbWlzc2luZywgYW5kIGNvbHVtbiBudW1iZXIgaXMgbm90IGd1YXJhbnRlZWRcbiAqICAgLSBJRTogICAgICBsaW5lIGFuZCBjb2x1bW4gbnVtYmVyIGZvciB0aGUgdG9wIGZyYW1lIG9ubHk7IHNvbWUgZnJhbWVzXG4gKiAgICAgICAgICAgICAgbWF5IGJlIG1pc3NpbmcsIGFuZCBjb2x1bW4gbnVtYmVyIGlzIG5vdCBndWFyYW50ZWVkXG4gKlxuICogSW4gdGhlb3J5LCBUcmFjZUtpdCBzaG91bGQgd29yayBvbiBhbGwgb2YgdGhlIGZvbGxvd2luZyB2ZXJzaW9uczpcbiAqICAgLSBJRTUuNSsgKG9ubHkgOC4wIHRlc3RlZClcbiAqICAgLSBGaXJlZm94IDAuOSsgKG9ubHkgMy41KyB0ZXN0ZWQpXG4gKiAgIC0gT3BlcmEgNysgKG9ubHkgMTAuNTAgdGVzdGVkOyB2ZXJzaW9ucyA5IGFuZCBlYXJsaWVyIG1heSByZXF1aXJlXG4gKiAgICAgRXhjZXB0aW9ucyBIYXZlIFN0YWNrdHJhY2UgdG8gYmUgZW5hYmxlZCBpbiBvcGVyYTpjb25maWcpXG4gKiAgIC0gU2FmYXJpIDMrIChvbmx5IDQrIHRlc3RlZClcbiAqICAgLSBDaHJvbWUgMSsgKG9ubHkgNSsgdGVzdGVkKVxuICogICAtIEtvbnF1ZXJvciAzLjUrICh1bnRlc3RlZClcbiAqXG4gKiBSZXF1aXJlcyBUcmFjZUtpdC5jb21wdXRlU3RhY2tUcmFjZS5cbiAqXG4gKiBUcmllcyB0byBjYXRjaCBhbGwgdW5oYW5kbGVkIGV4Y2VwdGlvbnMgYW5kIHJlcG9ydCB0aGVtIHRvIHRoZVxuICogc3Vic2NyaWJlZCBoYW5kbGVycy4gUGxlYXNlIG5vdGUgdGhhdCBUcmFjZUtpdC5yZXBvcnQgd2lsbCByZXRocm93IHRoZVxuICogZXhjZXB0aW9uLiBUaGlzIGlzIFJFUVVJUkVEIGluIG9yZGVyIHRvIGdldCBhIHVzZWZ1bCBzdGFjayB0cmFjZSBpbiBJRS5cbiAqIElmIHRoZSBleGNlcHRpb24gZG9lcyBub3QgcmVhY2ggdGhlIHRvcCBvZiB0aGUgYnJvd3NlciwgeW91IHdpbGwgb25seVxuICogZ2V0IGEgc3RhY2sgdHJhY2UgZnJvbSB0aGUgcG9pbnQgd2hlcmUgVHJhY2VLaXQucmVwb3J0IHdhcyBjYWxsZWQuXG4gKlxuICogSGFuZGxlcnMgcmVjZWl2ZSBhIHN0YWNrSW5mbyBvYmplY3QgYXMgZGVzY3JpYmVkIGluIHRoZVxuICogVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2UgZG9jcy5cbiAqL1xuVHJhY2VLaXQucmVwb3J0ID0gKGZ1bmN0aW9uIHJlcG9ydE1vZHVsZVdyYXBwZXIoKSB7XG4gIHZhciBoYW5kbGVycyA9IFtdLFxuICAgIGxhc3RBcmdzID0gbnVsbCxcbiAgICBsYXN0RXhjZXB0aW9uID0gbnVsbCxcbiAgICBsYXN0RXhjZXB0aW9uU3RhY2sgPSBudWxsO1xuXG4gIC8qKlxuICAgICAqIEFkZCBhIGNyYXNoIGhhbmRsZXIuXG4gICAgICogQHBhcmFtIHtGdW5jdGlvbn0gaGFuZGxlclxuICAgICAqL1xuICBmdW5jdGlvbiBzdWJzY3JpYmUoaGFuZGxlcikge1xuICAgIGluc3RhbGxHbG9iYWxIYW5kbGVyKCk7XG4gICAgaGFuZGxlcnMucHVzaChoYW5kbGVyKTtcbiAgfVxuXG4gIC8qKlxuICAgICAqIFJlbW92ZSBhIGNyYXNoIGhhbmRsZXIuXG4gICAgICogQHBhcmFtIHtGdW5jdGlvbn0gaGFuZGxlclxuICAgICAqL1xuICBmdW5jdGlvbiB1bnN1YnNjcmliZShoYW5kbGVyKSB7XG4gICAgZm9yICh2YXIgaSA9IGhhbmRsZXJzLmxlbmd0aCAtIDE7IGkgPj0gMDsgLS1pKSB7XG4gICAgICBpZiAoaGFuZGxlcnNbaV0gPT09IGhhbmRsZXIpIHtcbiAgICAgICAgaGFuZGxlcnMuc3BsaWNlKGksIDEpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgICAqIFJlbW92ZSBhbGwgY3Jhc2ggaGFuZGxlcnMuXG4gICAgICovXG4gIGZ1bmN0aW9uIHVuc3Vic2NyaWJlQWxsKCkge1xuICAgIHVuaW5zdGFsbEdsb2JhbEhhbmRsZXIoKTtcbiAgICBoYW5kbGVycyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICAgICogRGlzcGF0Y2ggc3RhY2sgaW5mb3JtYXRpb24gdG8gYWxsIGhhbmRsZXJzLlxuICAgICAqIEBwYXJhbSB7T2JqZWN0LjxzdHJpbmcsICo+fSBzdGFja1xuICAgICAqL1xuICBmdW5jdGlvbiBub3RpZnlIYW5kbGVycyhzdGFjaywgaXNXaW5kb3dFcnJvcikge1xuICAgIHZhciBleGNlcHRpb24gPSBudWxsO1xuICAgIGlmIChpc1dpbmRvd0Vycm9yICYmICFUcmFjZUtpdC5jb2xsZWN0V2luZG93RXJyb3JzKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGZvciAodmFyIGkgaW4gaGFuZGxlcnMpIHtcbiAgICAgIGlmIChoYW5kbGVycy5oYXNPd25Qcm9wZXJ0eShpKSkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGhhbmRsZXJzW2ldLmFwcGx5KG51bGwsIFtzdGFja10uY29uY2F0KF9zbGljZS5jYWxsKGFyZ3VtZW50cywgMikpKTtcbiAgICAgICAgfSBjYXRjaCAoaW5uZXIpIHtcbiAgICAgICAgICBleGNlcHRpb24gPSBpbm5lcjtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChleGNlcHRpb24pIHtcbiAgICAgIHRocm93IGV4Y2VwdGlvbjtcbiAgICB9XG4gIH1cblxuICB2YXIgX29sZE9uZXJyb3JIYW5kbGVyLCBfb25FcnJvckhhbmRsZXJJbnN0YWxsZWQ7XG5cbiAgLyoqXG4gICAgICogRW5zdXJlcyBhbGwgZ2xvYmFsIHVuaGFuZGxlZCBleGNlcHRpb25zIGFyZSByZWNvcmRlZC5cbiAgICAgKiBTdXBwb3J0ZWQgYnkgR2Vja28gYW5kIElFLlxuICAgICAqIEBwYXJhbSB7c3RyaW5nfSBtZXNzYWdlIEVycm9yIG1lc3NhZ2UuXG4gICAgICogQHBhcmFtIHtzdHJpbmd9IHVybCBVUkwgb2Ygc2NyaXB0IHRoYXQgZ2VuZXJhdGVkIHRoZSBleGNlcHRpb24uXG4gICAgICogQHBhcmFtIHsobnVtYmVyfHN0cmluZyl9IGxpbmVObyBUaGUgbGluZSBudW1iZXIgYXQgd2hpY2ggdGhlIGVycm9yXG4gICAgICogb2NjdXJyZWQuXG4gICAgICogQHBhcmFtIHs/KG51bWJlcnxzdHJpbmcpfSBjb2xObyBUaGUgY29sdW1uIG51bWJlciBhdCB3aGljaCB0aGUgZXJyb3JcbiAgICAgKiBvY2N1cnJlZC5cbiAgICAgKiBAcGFyYW0gez9FcnJvcn0gZXggVGhlIGFjdHVhbCBFcnJvciBvYmplY3QuXG4gICAgICovXG4gIGZ1bmN0aW9uIHRyYWNlS2l0V2luZG93T25FcnJvcihtZXNzYWdlLCB1cmwsIGxpbmVObywgY29sTm8sIGV4KSB7XG4gICAgdmFyIHN0YWNrID0gbnVsbDtcblxuICAgIGlmIChsYXN0RXhjZXB0aW9uU3RhY2spIHtcbiAgICAgIFRyYWNlS2l0LmNvbXB1dGVTdGFja1RyYWNlLmF1Z21lbnRTdGFja1RyYWNlV2l0aEluaXRpYWxFbGVtZW50KFxuICAgICAgICBsYXN0RXhjZXB0aW9uU3RhY2ssXG4gICAgICAgIHVybCxcbiAgICAgICAgbGluZU5vLFxuICAgICAgICBtZXNzYWdlXG4gICAgICApO1xuICAgICAgcHJvY2Vzc0xhc3RFeGNlcHRpb24oKTtcbiAgICB9IGVsc2UgaWYgKGV4ICYmIHV0aWxzLmlzRXJyb3IoZXgpKSB7XG4gICAgICAvLyBub24tc3RyaW5nIGBleGAgYXJnOyBhdHRlbXB0IHRvIGV4dHJhY3Qgc3RhY2sgdHJhY2VcblxuICAgICAgLy8gTmV3IGNocm9tZSBhbmQgYmxpbmsgc2VuZCBhbG9uZyBhIHJlYWwgZXJyb3Igb2JqZWN0XG4gICAgICAvLyBMZXQncyBqdXN0IHJlcG9ydCB0aGF0IGxpa2UgYSBub3JtYWwgZXJyb3IuXG4gICAgICAvLyBTZWU6IGh0dHBzOi8vbWlrZXdlc3Qub3JnLzIwMTMvMDgvZGVidWdnaW5nLXJ1bnRpbWUtZXJyb3JzLXdpdGgtd2luZG93LW9uZXJyb3JcbiAgICAgIHN0YWNrID0gVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2UoZXgpO1xuICAgICAgbm90aWZ5SGFuZGxlcnMoc3RhY2ssIHRydWUpO1xuICAgIH0gZWxzZSB7XG4gICAgICB2YXIgbG9jYXRpb24gPSB7XG4gICAgICAgIHVybDogdXJsLFxuICAgICAgICBsaW5lOiBsaW5lTm8sXG4gICAgICAgIGNvbHVtbjogY29sTm9cbiAgICAgIH07XG5cbiAgICAgIHZhciBuYW1lID0gdW5kZWZpbmVkO1xuICAgICAgdmFyIG1zZyA9IG1lc3NhZ2U7IC8vIG11c3QgYmUgbmV3IHZhciBvciB3aWxsIG1vZGlmeSBvcmlnaW5hbCBgYXJndW1lbnRzYFxuICAgICAgdmFyIGdyb3VwcztcbiAgICAgIGlmICh7fS50b1N0cmluZy5jYWxsKG1lc3NhZ2UpID09PSAnW29iamVjdCBTdHJpbmddJykge1xuICAgICAgICB2YXIgZ3JvdXBzID0gbWVzc2FnZS5tYXRjaChFUlJPUl9UWVBFU19SRSk7XG4gICAgICAgIGlmIChncm91cHMpIHtcbiAgICAgICAgICBuYW1lID0gZ3JvdXBzWzFdO1xuICAgICAgICAgIG1zZyA9IGdyb3Vwc1syXTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBsb2NhdGlvbi5mdW5jID0gVU5LTk9XTl9GVU5DVElPTjtcblxuICAgICAgc3RhY2sgPSB7XG4gICAgICAgIG5hbWU6IG5hbWUsXG4gICAgICAgIG1lc3NhZ2U6IG1zZyxcbiAgICAgICAgdXJsOiBnZXRMb2NhdGlvbkhyZWYoKSxcbiAgICAgICAgc3RhY2s6IFtsb2NhdGlvbl1cbiAgICAgIH07XG4gICAgICBub3RpZnlIYW5kbGVycyhzdGFjaywgdHJ1ZSk7XG4gICAgfVxuXG4gICAgaWYgKF9vbGRPbmVycm9ySGFuZGxlcikge1xuICAgICAgcmV0dXJuIF9vbGRPbmVycm9ySGFuZGxlci5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xuICAgIH1cblxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGluc3RhbGxHbG9iYWxIYW5kbGVyKCkge1xuICAgIGlmIChfb25FcnJvckhhbmRsZXJJbnN0YWxsZWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgX29sZE9uZXJyb3JIYW5kbGVyID0gX3dpbmRvdy5vbmVycm9yO1xuICAgIF93aW5kb3cub25lcnJvciA9IHRyYWNlS2l0V2luZG93T25FcnJvcjtcbiAgICBfb25FcnJvckhhbmRsZXJJbnN0YWxsZWQgPSB0cnVlO1xuICB9XG5cbiAgZnVuY3Rpb24gdW5pbnN0YWxsR2xvYmFsSGFuZGxlcigpIHtcbiAgICBpZiAoIV9vbkVycm9ySGFuZGxlckluc3RhbGxlZCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBfd2luZG93Lm9uZXJyb3IgPSBfb2xkT25lcnJvckhhbmRsZXI7XG4gICAgX29uRXJyb3JIYW5kbGVySW5zdGFsbGVkID0gZmFsc2U7XG4gICAgX29sZE9uZXJyb3JIYW5kbGVyID0gdW5kZWZpbmVkO1xuICB9XG5cbiAgZnVuY3Rpb24gcHJvY2Vzc0xhc3RFeGNlcHRpb24oKSB7XG4gICAgdmFyIF9sYXN0RXhjZXB0aW9uU3RhY2sgPSBsYXN0RXhjZXB0aW9uU3RhY2ssXG4gICAgICBfbGFzdEFyZ3MgPSBsYXN0QXJncztcbiAgICBsYXN0QXJncyA9IG51bGw7XG4gICAgbGFzdEV4Y2VwdGlvblN0YWNrID0gbnVsbDtcbiAgICBsYXN0RXhjZXB0aW9uID0gbnVsbDtcbiAgICBub3RpZnlIYW5kbGVycy5hcHBseShudWxsLCBbX2xhc3RFeGNlcHRpb25TdGFjaywgZmFsc2VdLmNvbmNhdChfbGFzdEFyZ3MpKTtcbiAgfVxuXG4gIC8qKlxuICAgICAqIFJlcG9ydHMgYW4gdW5oYW5kbGVkIEVycm9yIHRvIFRyYWNlS2l0LlxuICAgICAqIEBwYXJhbSB7RXJyb3J9IGV4XG4gICAgICogQHBhcmFtIHs/Ym9vbGVhbn0gcmV0aHJvdyBJZiBmYWxzZSwgZG8gbm90IHJlLXRocm93IHRoZSBleGNlcHRpb24uXG4gICAgICogT25seSB1c2VkIGZvciB3aW5kb3cub25lcnJvciB0byBub3QgY2F1c2UgYW4gaW5maW5pdGUgbG9vcCBvZlxuICAgICAqIHJldGhyb3dpbmcuXG4gICAgICovXG4gIGZ1bmN0aW9uIHJlcG9ydChleCwgcmV0aHJvdykge1xuICAgIHZhciBhcmdzID0gX3NsaWNlLmNhbGwoYXJndW1lbnRzLCAxKTtcbiAgICBpZiAobGFzdEV4Y2VwdGlvblN0YWNrKSB7XG4gICAgICBpZiAobGFzdEV4Y2VwdGlvbiA9PT0gZXgpIHtcbiAgICAgICAgcmV0dXJuOyAvLyBhbHJlYWR5IGNhdWdodCBieSBhbiBpbm5lciBjYXRjaCBibG9jaywgaWdub3JlXG4gICAgICB9IGVsc2Uge1xuICAgICAgICBwcm9jZXNzTGFzdEV4Y2VwdGlvbigpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHZhciBzdGFjayA9IFRyYWNlS2l0LmNvbXB1dGVTdGFja1RyYWNlKGV4KTtcbiAgICBsYXN0RXhjZXB0aW9uU3RhY2sgPSBzdGFjaztcbiAgICBsYXN0RXhjZXB0aW9uID0gZXg7XG4gICAgbGFzdEFyZ3MgPSBhcmdzO1xuXG4gICAgLy8gSWYgdGhlIHN0YWNrIHRyYWNlIGlzIGluY29tcGxldGUsIHdhaXQgZm9yIDIgc2Vjb25kcyBmb3JcbiAgICAvLyBzbG93IHNsb3cgSUUgdG8gc2VlIGlmIG9uZXJyb3Igb2NjdXJzIG9yIG5vdCBiZWZvcmUgcmVwb3J0aW5nXG4gICAgLy8gdGhpcyBleGNlcHRpb247IG90aGVyd2lzZSwgd2Ugd2lsbCBlbmQgdXAgd2l0aCBhbiBpbmNvbXBsZXRlXG4gICAgLy8gc3RhY2sgdHJhY2VcbiAgICBzZXRUaW1lb3V0KGZ1bmN0aW9uKCkge1xuICAgICAgaWYgKGxhc3RFeGNlcHRpb24gPT09IGV4KSB7XG4gICAgICAgIHByb2Nlc3NMYXN0RXhjZXB0aW9uKCk7XG4gICAgICB9XG4gICAgfSwgc3RhY2suaW5jb21wbGV0ZSA/IDIwMDAgOiAwKTtcblxuICAgIGlmIChyZXRocm93ICE9PSBmYWxzZSkge1xuICAgICAgdGhyb3cgZXg7IC8vIHJlLXRocm93IHRvIHByb3BhZ2F0ZSB0byB0aGUgdG9wIGxldmVsIChhbmQgY2F1c2Ugd2luZG93Lm9uZXJyb3IpXG4gICAgfVxuICB9XG5cbiAgcmVwb3J0LnN1YnNjcmliZSA9IHN1YnNjcmliZTtcbiAgcmVwb3J0LnVuc3Vic2NyaWJlID0gdW5zdWJzY3JpYmU7XG4gIHJlcG9ydC51bmluc3RhbGwgPSB1bnN1YnNjcmliZUFsbDtcbiAgcmV0dXJuIHJlcG9ydDtcbn0pKCk7XG5cbi8qKlxuICogVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2U6IGNyb3NzLWJyb3dzZXIgc3RhY2sgdHJhY2VzIGluIEphdmFTY3JpcHRcbiAqXG4gKiBTeW50YXg6XG4gKiAgIHMgPSBUcmFjZUtpdC5jb21wdXRlU3RhY2tUcmFjZShleGNlcHRpb24pIC8vIGNvbnNpZGVyIHVzaW5nIFRyYWNlS2l0LnJlcG9ydCBpbnN0ZWFkIChzZWUgYmVsb3cpXG4gKiBSZXR1cm5zOlxuICogICBzLm5hbWUgICAgICAgICAgICAgIC0gZXhjZXB0aW9uIG5hbWVcbiAqICAgcy5tZXNzYWdlICAgICAgICAgICAtIGV4Y2VwdGlvbiBtZXNzYWdlXG4gKiAgIHMuc3RhY2tbaV0udXJsICAgICAgLSBKYXZhU2NyaXB0IG9yIEhUTUwgZmlsZSBVUkxcbiAqICAgcy5zdGFja1tpXS5mdW5jICAgICAtIGZ1bmN0aW9uIG5hbWUsIG9yIGVtcHR5IGZvciBhbm9ueW1vdXMgZnVuY3Rpb25zIChpZiBndWVzc2luZyBkaWQgbm90IHdvcmspXG4gKiAgIHMuc3RhY2tbaV0uYXJncyAgICAgLSBhcmd1bWVudHMgcGFzc2VkIHRvIHRoZSBmdW5jdGlvbiwgaWYga25vd25cbiAqICAgcy5zdGFja1tpXS5saW5lICAgICAtIGxpbmUgbnVtYmVyLCBpZiBrbm93blxuICogICBzLnN0YWNrW2ldLmNvbHVtbiAgIC0gY29sdW1uIG51bWJlciwgaWYga25vd25cbiAqXG4gKiBTdXBwb3J0czpcbiAqICAgLSBGaXJlZm94OiAgZnVsbCBzdGFjayB0cmFjZSB3aXRoIGxpbmUgbnVtYmVycyBhbmQgdW5yZWxpYWJsZSBjb2x1bW5cbiAqICAgICAgICAgICAgICAgbnVtYmVyIG9uIHRvcCBmcmFtZVxuICogICAtIE9wZXJhIDEwOiBmdWxsIHN0YWNrIHRyYWNlIHdpdGggbGluZSBhbmQgY29sdW1uIG51bWJlcnNcbiAqICAgLSBPcGVyYSA5LTogZnVsbCBzdGFjayB0cmFjZSB3aXRoIGxpbmUgbnVtYmVyc1xuICogICAtIENocm9tZTogICBmdWxsIHN0YWNrIHRyYWNlIHdpdGggbGluZSBhbmQgY29sdW1uIG51bWJlcnNcbiAqICAgLSBTYWZhcmk6ICAgbGluZSBhbmQgY29sdW1uIG51bWJlciBmb3IgdGhlIHRvcG1vc3Qgc3RhY2t0cmFjZSBlbGVtZW50XG4gKiAgICAgICAgICAgICAgIG9ubHlcbiAqICAgLSBJRTogICAgICAgbm8gbGluZSBudW1iZXJzIHdoYXRzb2V2ZXJcbiAqXG4gKiBUcmllcyB0byBndWVzcyBuYW1lcyBvZiBhbm9ueW1vdXMgZnVuY3Rpb25zIGJ5IGxvb2tpbmcgZm9yIGFzc2lnbm1lbnRzXG4gKiBpbiB0aGUgc291cmNlIGNvZGUuIEluIElFIGFuZCBTYWZhcmksIHdlIGhhdmUgdG8gZ3Vlc3Mgc291cmNlIGZpbGUgbmFtZXNcbiAqIGJ5IHNlYXJjaGluZyBmb3IgZnVuY3Rpb24gYm9kaWVzIGluc2lkZSBhbGwgcGFnZSBzY3JpcHRzLiBUaGlzIHdpbGwgbm90XG4gKiB3b3JrIGZvciBzY3JpcHRzIHRoYXQgYXJlIGxvYWRlZCBjcm9zcy1kb21haW4uXG4gKiBIZXJlIGJlIGRyYWdvbnM6IHNvbWUgZnVuY3Rpb24gbmFtZXMgbWF5IGJlIGd1ZXNzZWQgaW5jb3JyZWN0bHksIGFuZFxuICogZHVwbGljYXRlIGZ1bmN0aW9ucyBtYXkgYmUgbWlzbWF0Y2hlZC5cbiAqXG4gKiBUcmFjZUtpdC5jb21wdXRlU3RhY2tUcmFjZSBzaG91bGQgb25seSBiZSB1c2VkIGZvciB0cmFjaW5nIHB1cnBvc2VzLlxuICogTG9nZ2luZyBvZiB1bmhhbmRsZWQgZXhjZXB0aW9ucyBzaG91bGQgYmUgZG9uZSB3aXRoIFRyYWNlS2l0LnJlcG9ydCxcbiAqIHdoaWNoIGJ1aWxkcyBvbiB0b3Agb2YgVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2UgYW5kIHByb3ZpZGVzIGJldHRlclxuICogSUUgc3VwcG9ydCBieSB1dGlsaXppbmcgdGhlIHdpbmRvdy5vbmVycm9yIGV2ZW50IHRvIHJldHJpZXZlIGluZm9ybWF0aW9uXG4gKiBhYm91dCB0aGUgdG9wIG9mIHRoZSBzdGFjay5cbiAqXG4gKiBOb3RlOiBJbiBJRSBhbmQgU2FmYXJpLCBubyBzdGFjayB0cmFjZSBpcyByZWNvcmRlZCBvbiB0aGUgRXJyb3Igb2JqZWN0LFxuICogc28gY29tcHV0ZVN0YWNrVHJhY2UgaW5zdGVhZCB3YWxrcyBpdHMgKm93biogY2hhaW4gb2YgY2FsbGVycy5cbiAqIFRoaXMgbWVhbnMgdGhhdDpcbiAqICAqIGluIFNhZmFyaSwgc29tZSBtZXRob2RzIG1heSBiZSBtaXNzaW5nIGZyb20gdGhlIHN0YWNrIHRyYWNlO1xuICogICogaW4gSUUsIHRoZSB0b3Btb3N0IGZ1bmN0aW9uIGluIHRoZSBzdGFjayB0cmFjZSB3aWxsIGFsd2F5cyBiZSB0aGVcbiAqICAgIGNhbGxlciBvZiBjb21wdXRlU3RhY2tUcmFjZS5cbiAqXG4gKiBUaGlzIGlzIG9rYXkgZm9yIHRyYWNpbmcgKGJlY2F1c2UgeW91IGFyZSBsaWtlbHkgdG8gYmUgY2FsbGluZ1xuICogY29tcHV0ZVN0YWNrVHJhY2UgZnJvbSB0aGUgZnVuY3Rpb24geW91IHdhbnQgdG8gYmUgdGhlIHRvcG1vc3QgZWxlbWVudFxuICogb2YgdGhlIHN0YWNrIHRyYWNlIGFueXdheSksIGJ1dCBub3Qgb2theSBmb3IgbG9nZ2luZyB1bmhhbmRsZWRcbiAqIGV4Y2VwdGlvbnMgKGJlY2F1c2UgeW91ciBjYXRjaCBibG9jayB3aWxsIGxpa2VseSBiZSBmYXIgYXdheSBmcm9tIHRoZVxuICogaW5uZXIgZnVuY3Rpb24gdGhhdCBhY3R1YWxseSBjYXVzZWQgdGhlIGV4Y2VwdGlvbikuXG4gKlxuICovXG5UcmFjZUtpdC5jb21wdXRlU3RhY2tUcmFjZSA9IChmdW5jdGlvbiBjb21wdXRlU3RhY2tUcmFjZVdyYXBwZXIoKSB7XG4gIC8vIENvbnRlbnRzIG9mIEV4Y2VwdGlvbiBpbiB2YXJpb3VzIGJyb3dzZXJzLlxuICAvL1xuICAvLyBTQUZBUkk6XG4gIC8vIGV4Lm1lc3NhZ2UgPSBDYW4ndCBmaW5kIHZhcmlhYmxlOiBxcVxuICAvLyBleC5saW5lID0gNTlcbiAgLy8gZXguc291cmNlSWQgPSA1ODAyMzgxOTJcbiAgLy8gZXguc291cmNlVVJMID0gaHR0cDovLy4uLlxuICAvLyBleC5leHByZXNzaW9uQmVnaW5PZmZzZXQgPSA5NlxuICAvLyBleC5leHByZXNzaW9uQ2FyZXRPZmZzZXQgPSA5OFxuICAvLyBleC5leHByZXNzaW9uRW5kT2Zmc2V0ID0gOThcbiAgLy8gZXgubmFtZSA9IFJlZmVyZW5jZUVycm9yXG4gIC8vXG4gIC8vIEZJUkVGT1g6XG4gIC8vIGV4Lm1lc3NhZ2UgPSBxcSBpcyBub3QgZGVmaW5lZFxuICAvLyBleC5maWxlTmFtZSA9IGh0dHA6Ly8uLi5cbiAgLy8gZXgubGluZU51bWJlciA9IDU5XG4gIC8vIGV4LmNvbHVtbk51bWJlciA9IDY5XG4gIC8vIGV4LnN0YWNrID0gLi4uc3RhY2sgdHJhY2UuLi4gKHNlZSB0aGUgZXhhbXBsZSBiZWxvdylcbiAgLy8gZXgubmFtZSA9IFJlZmVyZW5jZUVycm9yXG4gIC8vXG4gIC8vIENIUk9NRTpcbiAgLy8gZXgubWVzc2FnZSA9IHFxIGlzIG5vdCBkZWZpbmVkXG4gIC8vIGV4Lm5hbWUgPSBSZWZlcmVuY2VFcnJvclxuICAvLyBleC50eXBlID0gbm90X2RlZmluZWRcbiAgLy8gZXguYXJndW1lbnRzID0gWydhYSddXG4gIC8vIGV4LnN0YWNrID0gLi4uc3RhY2sgdHJhY2UuLi5cbiAgLy9cbiAgLy8gSU5URVJORVQgRVhQTE9SRVI6XG4gIC8vIGV4Lm1lc3NhZ2UgPSAuLi5cbiAgLy8gZXgubmFtZSA9IFJlZmVyZW5jZUVycm9yXG4gIC8vXG4gIC8vIE9QRVJBOlxuICAvLyBleC5tZXNzYWdlID0gLi4ubWVzc2FnZS4uLiAoc2VlIHRoZSBleGFtcGxlIGJlbG93KVxuICAvLyBleC5uYW1lID0gUmVmZXJlbmNlRXJyb3JcbiAgLy8gZXgub3BlcmEjc291cmNlbG9jID0gMTEgIChwcmV0dHkgbXVjaCB1c2VsZXNzLCBkdXBsaWNhdGVzIHRoZSBpbmZvIGluIGV4Lm1lc3NhZ2UpXG4gIC8vIGV4LnN0YWNrdHJhY2UgPSBuL2E7IHNlZSAnb3BlcmE6Y29uZmlnI1VzZXJQcmVmc3xFeGNlcHRpb25zIEhhdmUgU3RhY2t0cmFjZSdcblxuICAvKipcbiAgICAgKiBDb21wdXRlcyBzdGFjayB0cmFjZSBpbmZvcm1hdGlvbiBmcm9tIHRoZSBzdGFjayBwcm9wZXJ0eS5cbiAgICAgKiBDaHJvbWUgYW5kIEdlY2tvIHVzZSB0aGlzIHByb3BlcnR5LlxuICAgICAqIEBwYXJhbSB7RXJyb3J9IGV4XG4gICAgICogQHJldHVybiB7P09iamVjdC48c3RyaW5nLCAqPn0gU3RhY2sgdHJhY2UgaW5mb3JtYXRpb24uXG4gICAgICovXG4gIGZ1bmN0aW9uIGNvbXB1dGVTdGFja1RyYWNlRnJvbVN0YWNrUHJvcChleCkge1xuICAgIGlmICh0eXBlb2YgZXguc3RhY2sgPT09ICd1bmRlZmluZWQnIHx8ICFleC5zdGFjaykgcmV0dXJuO1xuXG4gICAgdmFyIGNocm9tZSA9IC9eXFxzKmF0ICguKj8pID9cXCgoKD86ZmlsZXxodHRwcz98YmxvYnxjaHJvbWUtZXh0ZW5zaW9ufG5hdGl2ZXxldmFsfHdlYnBhY2t8PGFub255bW91cz58W2Etel06fFxcLykuKj8pKD86OihcXGQrKSk/KD86OihcXGQrKSk/XFwpP1xccyokL2ksXG4gICAgICBnZWNrbyA9IC9eXFxzKiguKj8pKD86XFwoKC4qPylcXCkpPyg/Ol58QCkoKD86ZmlsZXxodHRwcz98YmxvYnxjaHJvbWV8d2VicGFja3xyZXNvdXJjZXxcXFtuYXRpdmUpLio/fFteQF0qYnVuZGxlKSg/OjooXFxkKykpPyg/OjooXFxkKykpP1xccyokL2ksXG4gICAgICB3aW5qcyA9IC9eXFxzKmF0ICg/OigoPzpcXFtvYmplY3Qgb2JqZWN0XFxdKT8uKykgKT9cXCg/KCg/OmZpbGV8bXMtYXBweHxodHRwcz98d2VicGFja3xibG9iKTouKj8pOihcXGQrKSg/OjooXFxkKykpP1xcKT9cXHMqJC9pLFxuICAgICAgLy8gVXNlZCB0byBhZGRpdGlvbmFsbHkgcGFyc2UgVVJML2xpbmUvY29sdW1uIGZyb20gZXZhbCBmcmFtZXNcbiAgICAgIGdlY2tvRXZhbCA9IC8oXFxTKykgbGluZSAoXFxkKykoPzogPiBldmFsIGxpbmUgXFxkKykqID4gZXZhbC9pLFxuICAgICAgY2hyb21lRXZhbCA9IC9cXCgoXFxTKikoPzo6KFxcZCspKSg/OjooXFxkKykpXFwpLyxcbiAgICAgIGxpbmVzID0gZXguc3RhY2suc3BsaXQoJ1xcbicpLFxuICAgICAgc3RhY2sgPSBbXSxcbiAgICAgIHN1Ym1hdGNoLFxuICAgICAgcGFydHMsXG4gICAgICBlbGVtZW50LFxuICAgICAgcmVmZXJlbmNlID0gL14oLiopIGlzIHVuZGVmaW5lZCQvLmV4ZWMoZXgubWVzc2FnZSk7XG5cbiAgICBmb3IgKHZhciBpID0gMCwgaiA9IGxpbmVzLmxlbmd0aDsgaSA8IGo7ICsraSkge1xuICAgICAgaWYgKChwYXJ0cyA9IGNocm9tZS5leGVjKGxpbmVzW2ldKSkpIHtcbiAgICAgICAgdmFyIGlzTmF0aXZlID0gcGFydHNbMl0gJiYgcGFydHNbMl0uaW5kZXhPZignbmF0aXZlJykgPT09IDA7IC8vIHN0YXJ0IG9mIGxpbmVcbiAgICAgICAgdmFyIGlzRXZhbCA9IHBhcnRzWzJdICYmIHBhcnRzWzJdLmluZGV4T2YoJ2V2YWwnKSA9PT0gMDsgLy8gc3RhcnQgb2YgbGluZVxuICAgICAgICBpZiAoaXNFdmFsICYmIChzdWJtYXRjaCA9IGNocm9tZUV2YWwuZXhlYyhwYXJ0c1syXSkpKSB7XG4gICAgICAgICAgLy8gdGhyb3cgb3V0IGV2YWwgbGluZS9jb2x1bW4gYW5kIHVzZSB0b3AtbW9zdCBsaW5lL2NvbHVtbiBudW1iZXJcbiAgICAgICAgICBwYXJ0c1syXSA9IHN1Ym1hdGNoWzFdOyAvLyB1cmxcbiAgICAgICAgICBwYXJ0c1szXSA9IHN1Ym1hdGNoWzJdOyAvLyBsaW5lXG4gICAgICAgICAgcGFydHNbNF0gPSBzdWJtYXRjaFszXTsgLy8gY29sdW1uXG4gICAgICAgIH1cbiAgICAgICAgZWxlbWVudCA9IHtcbiAgICAgICAgICB1cmw6ICFpc05hdGl2ZSA/IHBhcnRzWzJdIDogbnVsbCxcbiAgICAgICAgICBmdW5jOiBwYXJ0c1sxXSB8fCBVTktOT1dOX0ZVTkNUSU9OLFxuICAgICAgICAgIGFyZ3M6IGlzTmF0aXZlID8gW3BhcnRzWzJdXSA6IFtdLFxuICAgICAgICAgIGxpbmU6IHBhcnRzWzNdID8gK3BhcnRzWzNdIDogbnVsbCxcbiAgICAgICAgICBjb2x1bW46IHBhcnRzWzRdID8gK3BhcnRzWzRdIDogbnVsbFxuICAgICAgICB9O1xuICAgICAgfSBlbHNlIGlmICgocGFydHMgPSB3aW5qcy5leGVjKGxpbmVzW2ldKSkpIHtcbiAgICAgICAgZWxlbWVudCA9IHtcbiAgICAgICAgICB1cmw6IHBhcnRzWzJdLFxuICAgICAgICAgIGZ1bmM6IHBhcnRzWzFdIHx8IFVOS05PV05fRlVOQ1RJT04sXG4gICAgICAgICAgYXJnczogW10sXG4gICAgICAgICAgbGluZTogK3BhcnRzWzNdLFxuICAgICAgICAgIGNvbHVtbjogcGFydHNbNF0gPyArcGFydHNbNF0gOiBudWxsXG4gICAgICAgIH07XG4gICAgICB9IGVsc2UgaWYgKChwYXJ0cyA9IGdlY2tvLmV4ZWMobGluZXNbaV0pKSkge1xuICAgICAgICB2YXIgaXNFdmFsID0gcGFydHNbM10gJiYgcGFydHNbM10uaW5kZXhPZignID4gZXZhbCcpID4gLTE7XG4gICAgICAgIGlmIChpc0V2YWwgJiYgKHN1Ym1hdGNoID0gZ2Vja29FdmFsLmV4ZWMocGFydHNbM10pKSkge1xuICAgICAgICAgIC8vIHRocm93IG91dCBldmFsIGxpbmUvY29sdW1uIGFuZCB1c2UgdG9wLW1vc3QgbGluZSBudW1iZXJcbiAgICAgICAgICBwYXJ0c1szXSA9IHN1Ym1hdGNoWzFdO1xuICAgICAgICAgIHBhcnRzWzRdID0gc3VibWF0Y2hbMl07XG4gICAgICAgICAgcGFydHNbNV0gPSBudWxsOyAvLyBubyBjb2x1bW4gd2hlbiBldmFsXG4gICAgICAgIH0gZWxzZSBpZiAoaSA9PT0gMCAmJiAhcGFydHNbNV0gJiYgdHlwZW9mIGV4LmNvbHVtbk51bWJlciAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAvLyBGaXJlRm94IHVzZXMgdGhpcyBhd2Vzb21lIGNvbHVtbk51bWJlciBwcm9wZXJ0eSBmb3IgaXRzIHRvcCBmcmFtZVxuICAgICAgICAgIC8vIEFsc28gbm90ZSwgRmlyZWZveCdzIGNvbHVtbiBudW1iZXIgaXMgMC1iYXNlZCBhbmQgZXZlcnl0aGluZyBlbHNlIGV4cGVjdHMgMS1iYXNlZCxcbiAgICAgICAgICAvLyBzbyBhZGRpbmcgMVxuICAgICAgICAgIC8vIE5PVEU6IHRoaXMgaGFjayBkb2Vzbid0IHdvcmsgaWYgdG9wLW1vc3QgZnJhbWUgaXMgZXZhbFxuICAgICAgICAgIHN0YWNrWzBdLmNvbHVtbiA9IGV4LmNvbHVtbk51bWJlciArIDE7XG4gICAgICAgIH1cbiAgICAgICAgZWxlbWVudCA9IHtcbiAgICAgICAgICB1cmw6IHBhcnRzWzNdLFxuICAgICAgICAgIGZ1bmM6IHBhcnRzWzFdIHx8IFVOS05PV05fRlVOQ1RJT04sXG4gICAgICAgICAgYXJnczogcGFydHNbMl0gPyBwYXJ0c1syXS5zcGxpdCgnLCcpIDogW10sXG4gICAgICAgICAgbGluZTogcGFydHNbNF0gPyArcGFydHNbNF0gOiBudWxsLFxuICAgICAgICAgIGNvbHVtbjogcGFydHNbNV0gPyArcGFydHNbNV0gOiBudWxsXG4gICAgICAgIH07XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKCFlbGVtZW50LmZ1bmMgJiYgZWxlbWVudC5saW5lKSB7XG4gICAgICAgIGVsZW1lbnQuZnVuYyA9IFVOS05PV05fRlVOQ1RJT047XG4gICAgICB9XG5cbiAgICAgIHN0YWNrLnB1c2goZWxlbWVudCk7XG4gICAgfVxuXG4gICAgaWYgKCFzdGFjay5sZW5ndGgpIHtcbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cblxuICAgIHJldHVybiB7XG4gICAgICBuYW1lOiBleC5uYW1lLFxuICAgICAgbWVzc2FnZTogZXgubWVzc2FnZSxcbiAgICAgIHVybDogZ2V0TG9jYXRpb25IcmVmKCksXG4gICAgICBzdGFjazogc3RhY2tcbiAgICB9O1xuICB9XG5cbiAgLyoqXG4gICAgICogQWRkcyBpbmZvcm1hdGlvbiBhYm91dCB0aGUgZmlyc3QgZnJhbWUgdG8gaW5jb21wbGV0ZSBzdGFjayB0cmFjZXMuXG4gICAgICogU2FmYXJpIGFuZCBJRSByZXF1aXJlIHRoaXMgdG8gZ2V0IGNvbXBsZXRlIGRhdGEgb24gdGhlIGZpcnN0IGZyYW1lLlxuICAgICAqIEBwYXJhbSB7T2JqZWN0LjxzdHJpbmcsICo+fSBzdGFja0luZm8gU3RhY2sgdHJhY2UgaW5mb3JtYXRpb24gZnJvbVxuICAgICAqIG9uZSBvZiB0aGUgY29tcHV0ZSogbWV0aG9kcy5cbiAgICAgKiBAcGFyYW0ge3N0cmluZ30gdXJsIFRoZSBVUkwgb2YgdGhlIHNjcmlwdCB0aGF0IGNhdXNlZCBhbiBlcnJvci5cbiAgICAgKiBAcGFyYW0geyhudW1iZXJ8c3RyaW5nKX0gbGluZU5vIFRoZSBsaW5lIG51bWJlciBvZiB0aGUgc2NyaXB0IHRoYXRcbiAgICAgKiBjYXVzZWQgYW4gZXJyb3IuXG4gICAgICogQHBhcmFtIHtzdHJpbmc9fSBtZXNzYWdlIFRoZSBlcnJvciBnZW5lcmF0ZWQgYnkgdGhlIGJyb3dzZXIsIHdoaWNoXG4gICAgICogaG9wZWZ1bGx5IGNvbnRhaW5zIHRoZSBuYW1lIG9mIHRoZSBvYmplY3QgdGhhdCBjYXVzZWQgdGhlIGVycm9yLlxuICAgICAqIEByZXR1cm4ge2Jvb2xlYW59IFdoZXRoZXIgb3Igbm90IHRoZSBzdGFjayBpbmZvcm1hdGlvbiB3YXNcbiAgICAgKiBhdWdtZW50ZWQuXG4gICAgICovXG4gIGZ1bmN0aW9uIGF1Z21lbnRTdGFja1RyYWNlV2l0aEluaXRpYWxFbGVtZW50KHN0YWNrSW5mbywgdXJsLCBsaW5lTm8sIG1lc3NhZ2UpIHtcbiAgICB2YXIgaW5pdGlhbCA9IHtcbiAgICAgIHVybDogdXJsLFxuICAgICAgbGluZTogbGluZU5vXG4gICAgfTtcblxuICAgIGlmIChpbml0aWFsLnVybCAmJiBpbml0aWFsLmxpbmUpIHtcbiAgICAgIHN0YWNrSW5mby5pbmNvbXBsZXRlID0gZmFsc2U7XG5cbiAgICAgIGlmICghaW5pdGlhbC5mdW5jKSB7XG4gICAgICAgIGluaXRpYWwuZnVuYyA9IFVOS05PV05fRlVOQ1RJT047XG4gICAgICB9XG5cbiAgICAgIGlmIChzdGFja0luZm8uc3RhY2subGVuZ3RoID4gMCkge1xuICAgICAgICBpZiAoc3RhY2tJbmZvLnN0YWNrWzBdLnVybCA9PT0gaW5pdGlhbC51cmwpIHtcbiAgICAgICAgICBpZiAoc3RhY2tJbmZvLnN0YWNrWzBdLmxpbmUgPT09IGluaXRpYWwubGluZSkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlOyAvLyBhbHJlYWR5IGluIHN0YWNrIHRyYWNlXG4gICAgICAgICAgfSBlbHNlIGlmIChcbiAgICAgICAgICAgICFzdGFja0luZm8uc3RhY2tbMF0ubGluZSAmJlxuICAgICAgICAgICAgc3RhY2tJbmZvLnN0YWNrWzBdLmZ1bmMgPT09IGluaXRpYWwuZnVuY1xuICAgICAgICAgICkge1xuICAgICAgICAgICAgc3RhY2tJbmZvLnN0YWNrWzBdLmxpbmUgPSBpbml0aWFsLmxpbmU7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHN0YWNrSW5mby5zdGFjay51bnNoaWZ0KGluaXRpYWwpO1xuICAgICAgc3RhY2tJbmZvLnBhcnRpYWwgPSB0cnVlO1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfSBlbHNlIHtcbiAgICAgIHN0YWNrSW5mby5pbmNvbXBsZXRlID0gdHJ1ZTtcbiAgICB9XG5cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICAvKipcbiAgICAgKiBDb21wdXRlcyBzdGFjayB0cmFjZSBpbmZvcm1hdGlvbiBieSB3YWxraW5nIHRoZSBhcmd1bWVudHMuY2FsbGVyXG4gICAgICogY2hhaW4gYXQgdGhlIHRpbWUgdGhlIGV4Y2VwdGlvbiBvY2N1cnJlZC4gVGhpcyB3aWxsIGNhdXNlIGVhcmxpZXJcbiAgICAgKiBmcmFtZXMgdG8gYmUgbWlzc2VkIGJ1dCBpcyB0aGUgb25seSB3YXkgdG8gZ2V0IGFueSBzdGFjayB0cmFjZSBpblxuICAgICAqIFNhZmFyaSBhbmQgSUUuIFRoZSB0b3AgZnJhbWUgaXMgcmVzdG9yZWQgYnlcbiAgICAgKiB7QGxpbmsgYXVnbWVudFN0YWNrVHJhY2VXaXRoSW5pdGlhbEVsZW1lbnR9LlxuICAgICAqIEBwYXJhbSB7RXJyb3J9IGV4XG4gICAgICogQHJldHVybiB7P09iamVjdC48c3RyaW5nLCAqPn0gU3RhY2sgdHJhY2UgaW5mb3JtYXRpb24uXG4gICAgICovXG4gIGZ1bmN0aW9uIGNvbXB1dGVTdGFja1RyYWNlQnlXYWxraW5nQ2FsbGVyQ2hhaW4oZXgsIGRlcHRoKSB7XG4gICAgdmFyIGZ1bmN0aW9uTmFtZSA9IC9mdW5jdGlvblxccysoW18kYS16QS1aXFx4QTAtXFx1RkZGRl1bXyRhLXpBLVowLTlcXHhBMC1cXHVGRkZGXSopP1xccypcXCgvaSxcbiAgICAgIHN0YWNrID0gW10sXG4gICAgICBmdW5jcyA9IHt9LFxuICAgICAgcmVjdXJzaW9uID0gZmFsc2UsXG4gICAgICBwYXJ0cyxcbiAgICAgIGl0ZW0sXG4gICAgICBzb3VyY2U7XG5cbiAgICBmb3IgKFxuICAgICAgdmFyIGN1cnIgPSBjb21wdXRlU3RhY2tUcmFjZUJ5V2Fsa2luZ0NhbGxlckNoYWluLmNhbGxlcjtcbiAgICAgIGN1cnIgJiYgIXJlY3Vyc2lvbjtcbiAgICAgIGN1cnIgPSBjdXJyLmNhbGxlclxuICAgICkge1xuICAgICAgaWYgKGN1cnIgPT09IGNvbXB1dGVTdGFja1RyYWNlIHx8IGN1cnIgPT09IFRyYWNlS2l0LnJlcG9ydCkge1xuICAgICAgICAvLyBjb25zb2xlLmxvZygnc2tpcHBpbmcgaW50ZXJuYWwgZnVuY3Rpb24nKTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGl0ZW0gPSB7XG4gICAgICAgIHVybDogbnVsbCxcbiAgICAgICAgZnVuYzogVU5LTk9XTl9GVU5DVElPTixcbiAgICAgICAgbGluZTogbnVsbCxcbiAgICAgICAgY29sdW1uOiBudWxsXG4gICAgICB9O1xuXG4gICAgICBpZiAoY3Vyci5uYW1lKSB7XG4gICAgICAgIGl0ZW0uZnVuYyA9IGN1cnIubmFtZTtcbiAgICAgIH0gZWxzZSBpZiAoKHBhcnRzID0gZnVuY3Rpb25OYW1lLmV4ZWMoY3Vyci50b1N0cmluZygpKSkpIHtcbiAgICAgICAgaXRlbS5mdW5jID0gcGFydHNbMV07XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgaXRlbS5mdW5jID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGl0ZW0uZnVuYyA9IHBhcnRzLmlucHV0LnN1YnN0cmluZygwLCBwYXJ0cy5pbnB1dC5pbmRleE9mKCd7JykpO1xuICAgICAgICB9IGNhdGNoIChlKSB7fVxuICAgICAgfVxuXG4gICAgICBpZiAoZnVuY3NbJycgKyBjdXJyXSkge1xuICAgICAgICByZWN1cnNpb24gPSB0cnVlO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgZnVuY3NbJycgKyBjdXJyXSA9IHRydWU7XG4gICAgICB9XG5cbiAgICAgIHN0YWNrLnB1c2goaXRlbSk7XG4gICAgfVxuXG4gICAgaWYgKGRlcHRoKSB7XG4gICAgICAvLyBjb25zb2xlLmxvZygnZGVwdGggaXMgJyArIGRlcHRoKTtcbiAgICAgIC8vIGNvbnNvbGUubG9nKCdzdGFjayBpcyAnICsgc3RhY2subGVuZ3RoKTtcbiAgICAgIHN0YWNrLnNwbGljZSgwLCBkZXB0aCk7XG4gICAgfVxuXG4gICAgdmFyIHJlc3VsdCA9IHtcbiAgICAgIG5hbWU6IGV4Lm5hbWUsXG4gICAgICBtZXNzYWdlOiBleC5tZXNzYWdlLFxuICAgICAgdXJsOiBnZXRMb2NhdGlvbkhyZWYoKSxcbiAgICAgIHN0YWNrOiBzdGFja1xuICAgIH07XG4gICAgYXVnbWVudFN0YWNrVHJhY2VXaXRoSW5pdGlhbEVsZW1lbnQoXG4gICAgICByZXN1bHQsXG4gICAgICBleC5zb3VyY2VVUkwgfHwgZXguZmlsZU5hbWUsXG4gICAgICBleC5saW5lIHx8IGV4LmxpbmVOdW1iZXIsXG4gICAgICBleC5tZXNzYWdlIHx8IGV4LmRlc2NyaXB0aW9uXG4gICAgKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLyoqXG4gICAgICogQ29tcHV0ZXMgYSBzdGFjayB0cmFjZSBmb3IgYW4gZXhjZXB0aW9uLlxuICAgICAqIEBwYXJhbSB7RXJyb3J9IGV4XG4gICAgICogQHBhcmFtIHsoc3RyaW5nfG51bWJlcik9fSBkZXB0aFxuICAgICAqL1xuICBmdW5jdGlvbiBjb21wdXRlU3RhY2tUcmFjZShleCwgZGVwdGgpIHtcbiAgICB2YXIgc3RhY2sgPSBudWxsO1xuICAgIGRlcHRoID0gZGVwdGggPT0gbnVsbCA/IDAgOiArZGVwdGg7XG5cbiAgICB0cnkge1xuICAgICAgc3RhY2sgPSBjb21wdXRlU3RhY2tUcmFjZUZyb21TdGFja1Byb3AoZXgpO1xuICAgICAgaWYgKHN0YWNrKSB7XG4gICAgICAgIHJldHVybiBzdGFjaztcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBpZiAoVHJhY2VLaXQuZGVidWcpIHtcbiAgICAgICAgdGhyb3cgZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB0cnkge1xuICAgICAgc3RhY2sgPSBjb21wdXRlU3RhY2tUcmFjZUJ5V2Fsa2luZ0NhbGxlckNoYWluKGV4LCBkZXB0aCArIDEpO1xuICAgICAgaWYgKHN0YWNrKSB7XG4gICAgICAgIHJldHVybiBzdGFjaztcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBpZiAoVHJhY2VLaXQuZGVidWcpIHtcbiAgICAgICAgdGhyb3cgZTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHtcbiAgICAgIG5hbWU6IGV4Lm5hbWUsXG4gICAgICBtZXNzYWdlOiBleC5tZXNzYWdlLFxuICAgICAgdXJsOiBnZXRMb2NhdGlvbkhyZWYoKVxuICAgIH07XG4gIH1cblxuICBjb21wdXRlU3RhY2tUcmFjZS5hdWdtZW50U3RhY2tUcmFjZVdpdGhJbml0aWFsRWxlbWVudCA9IGF1Z21lbnRTdGFja1RyYWNlV2l0aEluaXRpYWxFbGVtZW50O1xuICBjb21wdXRlU3RhY2tUcmFjZS5jb21wdXRlU3RhY2tUcmFjZUZyb21TdGFja1Byb3AgPSBjb21wdXRlU3RhY2tUcmFjZUZyb21TdGFja1Byb3A7XG5cbiAgcmV0dXJuIGNvbXB1dGVTdGFja1RyYWNlO1xufSkoKTtcblxubW9kdWxlLmV4cG9ydHMgPSBUcmFjZUtpdDtcbiIsIi8qXG4ganNvbi1zdHJpbmdpZnktc2FmZVxuIExpa2UgSlNPTi5zdHJpbmdpZnksIGJ1dCBkb2Vzbid0IHRocm93IG9uIGNpcmN1bGFyIHJlZmVyZW5jZXMuXG5cbiBPcmlnaW5hbGx5IGZvcmtlZCBmcm9tIGh0dHBzOi8vZ2l0aHViLmNvbS9pc2FhY3MvanNvbi1zdHJpbmdpZnktc2FmZVxuIHZlcnNpb24gNS4wLjEgb24gMy84LzIwMTcgYW5kIG1vZGlmaWVkIHRvIGhhbmRsZSBFcnJvcnMgc2VyaWFsaXphdGlvblxuIGFuZCBJRTggY29tcGF0aWJpbGl0eS4gVGVzdHMgZm9yIHRoaXMgYXJlIGluIHRlc3QvdmVuZG9yLlxuXG4gSVNDIGxpY2Vuc2U6IGh0dHBzOi8vZ2l0aHViLmNvbS9pc2FhY3MvanNvbi1zdHJpbmdpZnktc2FmZS9ibG9iL21hc3Rlci9MSUNFTlNFXG4qL1xuXG5leHBvcnRzID0gbW9kdWxlLmV4cG9ydHMgPSBzdHJpbmdpZnk7XG5leHBvcnRzLmdldFNlcmlhbGl6ZSA9IHNlcmlhbGl6ZXI7XG5cbmZ1bmN0aW9uIGluZGV4T2YoaGF5c3RhY2ssIG5lZWRsZSkge1xuICBmb3IgKHZhciBpID0gMDsgaSA8IGhheXN0YWNrLmxlbmd0aDsgKytpKSB7XG4gICAgaWYgKGhheXN0YWNrW2ldID09PSBuZWVkbGUpIHJldHVybiBpO1xuICB9XG4gIHJldHVybiAtMTtcbn1cblxuZnVuY3Rpb24gc3RyaW5naWZ5KG9iaiwgcmVwbGFjZXIsIHNwYWNlcywgY3ljbGVSZXBsYWNlcikge1xuICByZXR1cm4gSlNPTi5zdHJpbmdpZnkob2JqLCBzZXJpYWxpemVyKHJlcGxhY2VyLCBjeWNsZVJlcGxhY2VyKSwgc3BhY2VzKTtcbn1cblxuLy8gaHR0cHM6Ly9naXRodWIuY29tL2Z0bGFicy9qcy1hYmJyZXZpYXRlL2Jsb2IvZmE3MDllNWYxMzllNzc3MGE3MTgyN2IxODkzZjIyNDE4MDk3ZmJkYS9pbmRleC5qcyNMOTUtTDEwNlxuZnVuY3Rpb24gc3RyaW5naWZ5RXJyb3IodmFsdWUpIHtcbiAgdmFyIGVyciA9IHtcbiAgICAvLyBUaGVzZSBwcm9wZXJ0aWVzIGFyZSBpbXBsZW1lbnRlZCBhcyBtYWdpY2FsIGdldHRlcnMgYW5kIGRvbid0IHNob3cgdXAgaW4gZm9yIGluXG4gICAgc3RhY2s6IHZhbHVlLnN0YWNrLFxuICAgIG1lc3NhZ2U6IHZhbHVlLm1lc3NhZ2UsXG4gICAgbmFtZTogdmFsdWUubmFtZVxuICB9O1xuXG4gIGZvciAodmFyIGkgaW4gdmFsdWUpIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHZhbHVlLCBpKSkge1xuICAgICAgZXJyW2ldID0gdmFsdWVbaV07XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIGVycjtcbn1cblxuZnVuY3Rpb24gc2VyaWFsaXplcihyZXBsYWNlciwgY3ljbGVSZXBsYWNlcikge1xuICB2YXIgc3RhY2sgPSBbXTtcbiAgdmFyIGtleXMgPSBbXTtcblxuICBpZiAoY3ljbGVSZXBsYWNlciA9PSBudWxsKSB7XG4gICAgY3ljbGVSZXBsYWNlciA9IGZ1bmN0aW9uKGtleSwgdmFsdWUpIHtcbiAgICAgIGlmIChzdGFja1swXSA9PT0gdmFsdWUpIHtcbiAgICAgICAgcmV0dXJuICdbQ2lyY3VsYXIgfl0nO1xuICAgICAgfVxuICAgICAgcmV0dXJuICdbQ2lyY3VsYXIgfi4nICsga2V5cy5zbGljZSgwLCBpbmRleE9mKHN0YWNrLCB2YWx1ZSkpLmpvaW4oJy4nKSArICddJztcbiAgICB9O1xuICB9XG5cbiAgcmV0dXJuIGZ1bmN0aW9uKGtleSwgdmFsdWUpIHtcbiAgICBpZiAoc3RhY2subGVuZ3RoID4gMCkge1xuICAgICAgdmFyIHRoaXNQb3MgPSBpbmRleE9mKHN0YWNrLCB0aGlzKTtcbiAgICAgIH50aGlzUG9zID8gc3RhY2suc3BsaWNlKHRoaXNQb3MgKyAxKSA6IHN0YWNrLnB1c2godGhpcyk7XG4gICAgICB+dGhpc1BvcyA/IGtleXMuc3BsaWNlKHRoaXNQb3MsIEluZmluaXR5LCBrZXkpIDoga2V5cy5wdXNoKGtleSk7XG5cbiAgICAgIGlmICh+aW5kZXhPZihzdGFjaywgdmFsdWUpKSB7XG4gICAgICAgIHZhbHVlID0gY3ljbGVSZXBsYWNlci5jYWxsKHRoaXMsIGtleSwgdmFsdWUpO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBzdGFjay5wdXNoKHZhbHVlKTtcbiAgICB9XG5cbiAgICByZXR1cm4gcmVwbGFjZXIgPT0gbnVsbFxuICAgICAgPyB2YWx1ZSBpbnN0YW5jZW9mIEVycm9yID8gc3RyaW5naWZ5RXJyb3IodmFsdWUpIDogdmFsdWVcbiAgICAgIDogcmVwbGFjZXIuY2FsbCh0aGlzLCBrZXksIHZhbHVlKTtcbiAgfTtcbn1cbiIsIi8vIENvcHlyaWdodCBKb3llbnQsIEluYy4gYW5kIG90aGVyIE5vZGUgY29udHJpYnV0b3JzLlxuLy9cbi8vIFBlcm1pc3Npb24gaXMgaGVyZWJ5IGdyYW50ZWQsIGZyZWUgb2YgY2hhcmdlLCB0byBhbnkgcGVyc29uIG9idGFpbmluZyBhXG4vLyBjb3B5IG9mIHRoaXMgc29mdHdhcmUgYW5kIGFzc29jaWF0ZWQgZG9jdW1lbnRhdGlvbiBmaWxlcyAodGhlXG4vLyBcIlNvZnR3YXJlXCIpLCB0byBkZWFsIGluIHRoZSBTb2Z0d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmdcbi8vIHdpdGhvdXQgbGltaXRhdGlvbiB0aGUgcmlnaHRzIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBtZXJnZSwgcHVibGlzaCxcbi8vIGRpc3RyaWJ1dGUsIHN1YmxpY2Vuc2UsIGFuZC9vciBzZWxsIGNvcGllcyBvZiB0aGUgU29mdHdhcmUsIGFuZCB0byBwZXJtaXRcbi8vIHBlcnNvbnMgdG8gd2hvbSB0aGUgU29mdHdhcmUgaXMgZnVybmlzaGVkIHRvIGRvIHNvLCBzdWJqZWN0IHRvIHRoZVxuLy8gZm9sbG93aW5nIGNvbmRpdGlvbnM6XG4vL1xuLy8gVGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2Ugc2hhbGwgYmUgaW5jbHVkZWRcbi8vIGluIGFsbCBjb3BpZXMgb3Igc3Vic3RhbnRpYWwgcG9ydGlvbnMgb2YgdGhlIFNvZnR3YXJlLlxuLy9cbi8vIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIsIFdJVEhPVVQgV0FSUkFOVFkgT0YgQU5ZIEtJTkQsIEVYUFJFU1Ncbi8vIE9SIElNUExJRUQsIElOQ0xVRElORyBCVVQgTk9UIExJTUlURUQgVE8gVEhFIFdBUlJBTlRJRVMgT0Zcbi8vIE1FUkNIQU5UQUJJTElUWSwgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UgQU5EIE5PTklORlJJTkdFTUVOVC4gSU5cbi8vIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1JTIE9SIENPUFlSSUdIVCBIT0xERVJTIEJFIExJQUJMRSBGT1IgQU5ZIENMQUlNLFxuLy8gREFNQUdFUyBPUiBPVEhFUiBMSUFCSUxJVFksIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBUT1JUIE9SXG4vLyBPVEhFUldJU0UsIEFSSVNJTkcgRlJPTSwgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgU09GVFdBUkUgT1IgVEhFXG4vLyBVU0UgT1IgT1RIRVIgREVBTElOR1MgSU4gVEhFIFNPRlRXQVJFLlxuXG4ndXNlIHN0cmljdCc7XG5cbnZhciBwdW55Y29kZSA9IHJlcXVpcmUoJ3B1bnljb2RlJyk7XG52YXIgdXRpbCA9IHJlcXVpcmUoJy4vdXRpbCcpO1xuXG5leHBvcnRzLnBhcnNlID0gdXJsUGFyc2U7XG5leHBvcnRzLnJlc29sdmUgPSB1cmxSZXNvbHZlO1xuZXhwb3J0cy5yZXNvbHZlT2JqZWN0ID0gdXJsUmVzb2x2ZU9iamVjdDtcbmV4cG9ydHMuZm9ybWF0ID0gdXJsRm9ybWF0O1xuXG5leHBvcnRzLlVybCA9IFVybDtcblxuZnVuY3Rpb24gVXJsKCkge1xuICB0aGlzLnByb3RvY29sID0gbnVsbDtcbiAgdGhpcy5zbGFzaGVzID0gbnVsbDtcbiAgdGhpcy5hdXRoID0gbnVsbDtcbiAgdGhpcy5ob3N0ID0gbnVsbDtcbiAgdGhpcy5wb3J0ID0gbnVsbDtcbiAgdGhpcy5ob3N0bmFtZSA9IG51bGw7XG4gIHRoaXMuaGFzaCA9IG51bGw7XG4gIHRoaXMuc2VhcmNoID0gbnVsbDtcbiAgdGhpcy5xdWVyeSA9IG51bGw7XG4gIHRoaXMucGF0aG5hbWUgPSBudWxsO1xuICB0aGlzLnBhdGggPSBudWxsO1xuICB0aGlzLmhyZWYgPSBudWxsO1xufVxuXG4vLyBSZWZlcmVuY2U6IFJGQyAzOTg2LCBSRkMgMTgwOCwgUkZDIDIzOTZcblxuLy8gZGVmaW5lIHRoZXNlIGhlcmUgc28gYXQgbGVhc3QgdGhleSBvbmx5IGhhdmUgdG8gYmVcbi8vIGNvbXBpbGVkIG9uY2Ugb24gdGhlIGZpcnN0IG1vZHVsZSBsb2FkLlxudmFyIHByb3RvY29sUGF0dGVybiA9IC9eKFthLXowLTkuKy1dKzopL2ksXG4gICAgcG9ydFBhdHRlcm4gPSAvOlswLTldKiQvLFxuXG4gICAgLy8gU3BlY2lhbCBjYXNlIGZvciBhIHNpbXBsZSBwYXRoIFVSTFxuICAgIHNpbXBsZVBhdGhQYXR0ZXJuID0gL14oXFwvXFwvPyg/IVxcLylbXlxcP1xcc10qKShcXD9bXlxcc10qKT8kLyxcblxuICAgIC8vIFJGQyAyMzk2OiBjaGFyYWN0ZXJzIHJlc2VydmVkIGZvciBkZWxpbWl0aW5nIFVSTHMuXG4gICAgLy8gV2UgYWN0dWFsbHkganVzdCBhdXRvLWVzY2FwZSB0aGVzZS5cbiAgICBkZWxpbXMgPSBbJzwnLCAnPicsICdcIicsICdgJywgJyAnLCAnXFxyJywgJ1xcbicsICdcXHQnXSxcblxuICAgIC8vIFJGQyAyMzk2OiBjaGFyYWN0ZXJzIG5vdCBhbGxvd2VkIGZvciB2YXJpb3VzIHJlYXNvbnMuXG4gICAgdW53aXNlID0gWyd7JywgJ30nLCAnfCcsICdcXFxcJywgJ14nLCAnYCddLmNvbmNhdChkZWxpbXMpLFxuXG4gICAgLy8gQWxsb3dlZCBieSBSRkNzLCBidXQgY2F1c2Ugb2YgWFNTIGF0dGFja3MuICBBbHdheXMgZXNjYXBlIHRoZXNlLlxuICAgIGF1dG9Fc2NhcGUgPSBbJ1xcJyddLmNvbmNhdCh1bndpc2UpLFxuICAgIC8vIENoYXJhY3RlcnMgdGhhdCBhcmUgbmV2ZXIgZXZlciBhbGxvd2VkIGluIGEgaG9zdG5hbWUuXG4gICAgLy8gTm90ZSB0aGF0IGFueSBpbnZhbGlkIGNoYXJzIGFyZSBhbHNvIGhhbmRsZWQsIGJ1dCB0aGVzZVxuICAgIC8vIGFyZSB0aGUgb25lcyB0aGF0IGFyZSAqZXhwZWN0ZWQqIHRvIGJlIHNlZW4sIHNvIHdlIGZhc3QtcGF0aFxuICAgIC8vIHRoZW0uXG4gICAgbm9uSG9zdENoYXJzID0gWyclJywgJy8nLCAnPycsICc7JywgJyMnXS5jb25jYXQoYXV0b0VzY2FwZSksXG4gICAgaG9zdEVuZGluZ0NoYXJzID0gWycvJywgJz8nLCAnIyddLFxuICAgIGhvc3RuYW1lTWF4TGVuID0gMjU1LFxuICAgIGhvc3RuYW1lUGFydFBhdHRlcm4gPSAvXlsrYS16MC05QS1aXy1dezAsNjN9JC8sXG4gICAgaG9zdG5hbWVQYXJ0U3RhcnQgPSAvXihbK2EtejAtOUEtWl8tXXswLDYzfSkoLiopJC8sXG4gICAgLy8gcHJvdG9jb2xzIHRoYXQgY2FuIGFsbG93IFwidW5zYWZlXCIgYW5kIFwidW53aXNlXCIgY2hhcnMuXG4gICAgdW5zYWZlUHJvdG9jb2wgPSB7XG4gICAgICAnamF2YXNjcmlwdCc6IHRydWUsXG4gICAgICAnamF2YXNjcmlwdDonOiB0cnVlXG4gICAgfSxcbiAgICAvLyBwcm90b2NvbHMgdGhhdCBuZXZlciBoYXZlIGEgaG9zdG5hbWUuXG4gICAgaG9zdGxlc3NQcm90b2NvbCA9IHtcbiAgICAgICdqYXZhc2NyaXB0JzogdHJ1ZSxcbiAgICAgICdqYXZhc2NyaXB0Oic6IHRydWVcbiAgICB9LFxuICAgIC8vIHByb3RvY29scyB0aGF0IGFsd2F5cyBjb250YWluIGEgLy8gYml0LlxuICAgIHNsYXNoZWRQcm90b2NvbCA9IHtcbiAgICAgICdodHRwJzogdHJ1ZSxcbiAgICAgICdodHRwcyc6IHRydWUsXG4gICAgICAnZnRwJzogdHJ1ZSxcbiAgICAgICdnb3BoZXInOiB0cnVlLFxuICAgICAgJ2ZpbGUnOiB0cnVlLFxuICAgICAgJ2h0dHA6JzogdHJ1ZSxcbiAgICAgICdodHRwczonOiB0cnVlLFxuICAgICAgJ2Z0cDonOiB0cnVlLFxuICAgICAgJ2dvcGhlcjonOiB0cnVlLFxuICAgICAgJ2ZpbGU6JzogdHJ1ZVxuICAgIH0sXG4gICAgcXVlcnlzdHJpbmcgPSByZXF1aXJlKCdxdWVyeXN0cmluZycpO1xuXG5mdW5jdGlvbiB1cmxQYXJzZSh1cmwsIHBhcnNlUXVlcnlTdHJpbmcsIHNsYXNoZXNEZW5vdGVIb3N0KSB7XG4gIGlmICh1cmwgJiYgdXRpbC5pc09iamVjdCh1cmwpICYmIHVybCBpbnN0YW5jZW9mIFVybCkgcmV0dXJuIHVybDtcblxuICB2YXIgdSA9IG5ldyBVcmw7XG4gIHUucGFyc2UodXJsLCBwYXJzZVF1ZXJ5U3RyaW5nLCBzbGFzaGVzRGVub3RlSG9zdCk7XG4gIHJldHVybiB1O1xufVxuXG5VcmwucHJvdG90eXBlLnBhcnNlID0gZnVuY3Rpb24odXJsLCBwYXJzZVF1ZXJ5U3RyaW5nLCBzbGFzaGVzRGVub3RlSG9zdCkge1xuICBpZiAoIXV0aWwuaXNTdHJpbmcodXJsKSkge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJQYXJhbWV0ZXIgJ3VybCcgbXVzdCBiZSBhIHN0cmluZywgbm90IFwiICsgdHlwZW9mIHVybCk7XG4gIH1cblxuICAvLyBDb3B5IGNocm9tZSwgSUUsIG9wZXJhIGJhY2tzbGFzaC1oYW5kbGluZyBiZWhhdmlvci5cbiAgLy8gQmFjayBzbGFzaGVzIGJlZm9yZSB0aGUgcXVlcnkgc3RyaW5nIGdldCBjb252ZXJ0ZWQgdG8gZm9yd2FyZCBzbGFzaGVzXG4gIC8vIFNlZTogaHR0cHM6Ly9jb2RlLmdvb2dsZS5jb20vcC9jaHJvbWl1bS9pc3N1ZXMvZGV0YWlsP2lkPTI1OTE2XG4gIHZhciBxdWVyeUluZGV4ID0gdXJsLmluZGV4T2YoJz8nKSxcbiAgICAgIHNwbGl0dGVyID1cbiAgICAgICAgICAocXVlcnlJbmRleCAhPT0gLTEgJiYgcXVlcnlJbmRleCA8IHVybC5pbmRleE9mKCcjJykpID8gJz8nIDogJyMnLFxuICAgICAgdVNwbGl0ID0gdXJsLnNwbGl0KHNwbGl0dGVyKSxcbiAgICAgIHNsYXNoUmVnZXggPSAvXFxcXC9nO1xuICB1U3BsaXRbMF0gPSB1U3BsaXRbMF0ucmVwbGFjZShzbGFzaFJlZ2V4LCAnLycpO1xuICB1cmwgPSB1U3BsaXQuam9pbihzcGxpdHRlcik7XG5cbiAgdmFyIHJlc3QgPSB1cmw7XG5cbiAgLy8gdHJpbSBiZWZvcmUgcHJvY2VlZGluZy5cbiAgLy8gVGhpcyBpcyB0byBzdXBwb3J0IHBhcnNlIHN0dWZmIGxpa2UgXCIgIGh0dHA6Ly9mb28uY29tICBcXG5cIlxuICByZXN0ID0gcmVzdC50cmltKCk7XG5cbiAgaWYgKCFzbGFzaGVzRGVub3RlSG9zdCAmJiB1cmwuc3BsaXQoJyMnKS5sZW5ndGggPT09IDEpIHtcbiAgICAvLyBUcnkgZmFzdCBwYXRoIHJlZ2V4cFxuICAgIHZhciBzaW1wbGVQYXRoID0gc2ltcGxlUGF0aFBhdHRlcm4uZXhlYyhyZXN0KTtcbiAgICBpZiAoc2ltcGxlUGF0aCkge1xuICAgICAgdGhpcy5wYXRoID0gcmVzdDtcbiAgICAgIHRoaXMuaHJlZiA9IHJlc3Q7XG4gICAgICB0aGlzLnBhdGhuYW1lID0gc2ltcGxlUGF0aFsxXTtcbiAgICAgIGlmIChzaW1wbGVQYXRoWzJdKSB7XG4gICAgICAgIHRoaXMuc2VhcmNoID0gc2ltcGxlUGF0aFsyXTtcbiAgICAgICAgaWYgKHBhcnNlUXVlcnlTdHJpbmcpIHtcbiAgICAgICAgICB0aGlzLnF1ZXJ5ID0gcXVlcnlzdHJpbmcucGFyc2UodGhpcy5zZWFyY2guc3Vic3RyKDEpKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB0aGlzLnF1ZXJ5ID0gdGhpcy5zZWFyY2guc3Vic3RyKDEpO1xuICAgICAgICB9XG4gICAgICB9IGVsc2UgaWYgKHBhcnNlUXVlcnlTdHJpbmcpIHtcbiAgICAgICAgdGhpcy5zZWFyY2ggPSAnJztcbiAgICAgICAgdGhpcy5xdWVyeSA9IHt9O1xuICAgICAgfVxuICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICB9XG5cbiAgdmFyIHByb3RvID0gcHJvdG9jb2xQYXR0ZXJuLmV4ZWMocmVzdCk7XG4gIGlmIChwcm90bykge1xuICAgIHByb3RvID0gcHJvdG9bMF07XG4gICAgdmFyIGxvd2VyUHJvdG8gPSBwcm90by50b0xvd2VyQ2FzZSgpO1xuICAgIHRoaXMucHJvdG9jb2wgPSBsb3dlclByb3RvO1xuICAgIHJlc3QgPSByZXN0LnN1YnN0cihwcm90by5sZW5ndGgpO1xuICB9XG5cbiAgLy8gZmlndXJlIG91dCBpZiBpdCdzIGdvdCBhIGhvc3RcbiAgLy8gdXNlckBzZXJ2ZXIgaXMgKmFsd2F5cyogaW50ZXJwcmV0ZWQgYXMgYSBob3N0bmFtZSwgYW5kIHVybFxuICAvLyByZXNvbHV0aW9uIHdpbGwgdHJlYXQgLy9mb28vYmFyIGFzIGhvc3Q9Zm9vLHBhdGg9YmFyIGJlY2F1c2UgdGhhdCdzXG4gIC8vIGhvdyB0aGUgYnJvd3NlciByZXNvbHZlcyByZWxhdGl2ZSBVUkxzLlxuICBpZiAoc2xhc2hlc0Rlbm90ZUhvc3QgfHwgcHJvdG8gfHwgcmVzdC5tYXRjaCgvXlxcL1xcL1teQFxcL10rQFteQFxcL10rLykpIHtcbiAgICB2YXIgc2xhc2hlcyA9IHJlc3Quc3Vic3RyKDAsIDIpID09PSAnLy8nO1xuICAgIGlmIChzbGFzaGVzICYmICEocHJvdG8gJiYgaG9zdGxlc3NQcm90b2NvbFtwcm90b10pKSB7XG4gICAgICByZXN0ID0gcmVzdC5zdWJzdHIoMik7XG4gICAgICB0aGlzLnNsYXNoZXMgPSB0cnVlO1xuICAgIH1cbiAgfVxuXG4gIGlmICghaG9zdGxlc3NQcm90b2NvbFtwcm90b10gJiZcbiAgICAgIChzbGFzaGVzIHx8IChwcm90byAmJiAhc2xhc2hlZFByb3RvY29sW3Byb3RvXSkpKSB7XG5cbiAgICAvLyB0aGVyZSdzIGEgaG9zdG5hbWUuXG4gICAgLy8gdGhlIGZpcnN0IGluc3RhbmNlIG9mIC8sID8sIDssIG9yICMgZW5kcyB0aGUgaG9zdC5cbiAgICAvL1xuICAgIC8vIElmIHRoZXJlIGlzIGFuIEAgaW4gdGhlIGhvc3RuYW1lLCB0aGVuIG5vbi1ob3N0IGNoYXJzICphcmUqIGFsbG93ZWRcbiAgICAvLyB0byB0aGUgbGVmdCBvZiB0aGUgbGFzdCBAIHNpZ24sIHVubGVzcyBzb21lIGhvc3QtZW5kaW5nIGNoYXJhY3RlclxuICAgIC8vIGNvbWVzICpiZWZvcmUqIHRoZSBALXNpZ24uXG4gICAgLy8gVVJMcyBhcmUgb2Jub3hpb3VzLlxuICAgIC8vXG4gICAgLy8gZXg6XG4gICAgLy8gaHR0cDovL2FAYkBjLyA9PiB1c2VyOmFAYiBob3N0OmNcbiAgICAvLyBodHRwOi8vYUBiP0BjID0+IHVzZXI6YSBob3N0OmMgcGF0aDovP0BjXG5cbiAgICAvLyB2MC4xMiBUT0RPKGlzYWFjcyk6IFRoaXMgaXMgbm90IHF1aXRlIGhvdyBDaHJvbWUgZG9lcyB0aGluZ3MuXG4gICAgLy8gUmV2aWV3IG91ciB0ZXN0IGNhc2UgYWdhaW5zdCBicm93c2VycyBtb3JlIGNvbXByZWhlbnNpdmVseS5cblxuICAgIC8vIGZpbmQgdGhlIGZpcnN0IGluc3RhbmNlIG9mIGFueSBob3N0RW5kaW5nQ2hhcnNcbiAgICB2YXIgaG9zdEVuZCA9IC0xO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaG9zdEVuZGluZ0NoYXJzLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgaGVjID0gcmVzdC5pbmRleE9mKGhvc3RFbmRpbmdDaGFyc1tpXSk7XG4gICAgICBpZiAoaGVjICE9PSAtMSAmJiAoaG9zdEVuZCA9PT0gLTEgfHwgaGVjIDwgaG9zdEVuZCkpXG4gICAgICAgIGhvc3RFbmQgPSBoZWM7XG4gICAgfVxuXG4gICAgLy8gYXQgdGhpcyBwb2ludCwgZWl0aGVyIHdlIGhhdmUgYW4gZXhwbGljaXQgcG9pbnQgd2hlcmUgdGhlXG4gICAgLy8gYXV0aCBwb3J0aW9uIGNhbm5vdCBnbyBwYXN0LCBvciB0aGUgbGFzdCBAIGNoYXIgaXMgdGhlIGRlY2lkZXIuXG4gICAgdmFyIGF1dGgsIGF0U2lnbjtcbiAgICBpZiAoaG9zdEVuZCA9PT0gLTEpIHtcbiAgICAgIC8vIGF0U2lnbiBjYW4gYmUgYW55d2hlcmUuXG4gICAgICBhdFNpZ24gPSByZXN0Lmxhc3RJbmRleE9mKCdAJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIGF0U2lnbiBtdXN0IGJlIGluIGF1dGggcG9ydGlvbi5cbiAgICAgIC8vIGh0dHA6Ly9hQGIvY0BkID0+IGhvc3Q6YiBhdXRoOmEgcGF0aDovY0BkXG4gICAgICBhdFNpZ24gPSByZXN0Lmxhc3RJbmRleE9mKCdAJywgaG9zdEVuZCk7XG4gICAgfVxuXG4gICAgLy8gTm93IHdlIGhhdmUgYSBwb3J0aW9uIHdoaWNoIGlzIGRlZmluaXRlbHkgdGhlIGF1dGguXG4gICAgLy8gUHVsbCB0aGF0IG9mZi5cbiAgICBpZiAoYXRTaWduICE9PSAtMSkge1xuICAgICAgYXV0aCA9IHJlc3Quc2xpY2UoMCwgYXRTaWduKTtcbiAgICAgIHJlc3QgPSByZXN0LnNsaWNlKGF0U2lnbiArIDEpO1xuICAgICAgdGhpcy5hdXRoID0gZGVjb2RlVVJJQ29tcG9uZW50KGF1dGgpO1xuICAgIH1cblxuICAgIC8vIHRoZSBob3N0IGlzIHRoZSByZW1haW5pbmcgdG8gdGhlIGxlZnQgb2YgdGhlIGZpcnN0IG5vbi1ob3N0IGNoYXJcbiAgICBob3N0RW5kID0gLTE7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBub25Ib3N0Q2hhcnMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciBoZWMgPSByZXN0LmluZGV4T2Yobm9uSG9zdENoYXJzW2ldKTtcbiAgICAgIGlmIChoZWMgIT09IC0xICYmIChob3N0RW5kID09PSAtMSB8fCBoZWMgPCBob3N0RW5kKSlcbiAgICAgICAgaG9zdEVuZCA9IGhlYztcbiAgICB9XG4gICAgLy8gaWYgd2Ugc3RpbGwgaGF2ZSBub3QgaGl0IGl0LCB0aGVuIHRoZSBlbnRpcmUgdGhpbmcgaXMgYSBob3N0LlxuICAgIGlmIChob3N0RW5kID09PSAtMSlcbiAgICAgIGhvc3RFbmQgPSByZXN0Lmxlbmd0aDtcblxuICAgIHRoaXMuaG9zdCA9IHJlc3Quc2xpY2UoMCwgaG9zdEVuZCk7XG4gICAgcmVzdCA9IHJlc3Quc2xpY2UoaG9zdEVuZCk7XG5cbiAgICAvLyBwdWxsIG91dCBwb3J0LlxuICAgIHRoaXMucGFyc2VIb3N0KCk7XG5cbiAgICAvLyB3ZSd2ZSBpbmRpY2F0ZWQgdGhhdCB0aGVyZSBpcyBhIGhvc3RuYW1lLFxuICAgIC8vIHNvIGV2ZW4gaWYgaXQncyBlbXB0eSwgaXQgaGFzIHRvIGJlIHByZXNlbnQuXG4gICAgdGhpcy5ob3N0bmFtZSA9IHRoaXMuaG9zdG5hbWUgfHwgJyc7XG5cbiAgICAvLyBpZiBob3N0bmFtZSBiZWdpbnMgd2l0aCBbIGFuZCBlbmRzIHdpdGggXVxuICAgIC8vIGFzc3VtZSB0aGF0IGl0J3MgYW4gSVB2NiBhZGRyZXNzLlxuICAgIHZhciBpcHY2SG9zdG5hbWUgPSB0aGlzLmhvc3RuYW1lWzBdID09PSAnWycgJiZcbiAgICAgICAgdGhpcy5ob3N0bmFtZVt0aGlzLmhvc3RuYW1lLmxlbmd0aCAtIDFdID09PSAnXSc7XG5cbiAgICAvLyB2YWxpZGF0ZSBhIGxpdHRsZS5cbiAgICBpZiAoIWlwdjZIb3N0bmFtZSkge1xuICAgICAgdmFyIGhvc3RwYXJ0cyA9IHRoaXMuaG9zdG5hbWUuc3BsaXQoL1xcLi8pO1xuICAgICAgZm9yICh2YXIgaSA9IDAsIGwgPSBob3N0cGFydHMubGVuZ3RoOyBpIDwgbDsgaSsrKSB7XG4gICAgICAgIHZhciBwYXJ0ID0gaG9zdHBhcnRzW2ldO1xuICAgICAgICBpZiAoIXBhcnQpIGNvbnRpbnVlO1xuICAgICAgICBpZiAoIXBhcnQubWF0Y2goaG9zdG5hbWVQYXJ0UGF0dGVybikpIHtcbiAgICAgICAgICB2YXIgbmV3cGFydCA9ICcnO1xuICAgICAgICAgIGZvciAodmFyIGogPSAwLCBrID0gcGFydC5sZW5ndGg7IGogPCBrOyBqKyspIHtcbiAgICAgICAgICAgIGlmIChwYXJ0LmNoYXJDb2RlQXQoaikgPiAxMjcpIHtcbiAgICAgICAgICAgICAgLy8gd2UgcmVwbGFjZSBub24tQVNDSUkgY2hhciB3aXRoIGEgdGVtcG9yYXJ5IHBsYWNlaG9sZGVyXG4gICAgICAgICAgICAgIC8vIHdlIG5lZWQgdGhpcyB0byBtYWtlIHN1cmUgc2l6ZSBvZiBob3N0bmFtZSBpcyBub3RcbiAgICAgICAgICAgICAgLy8gYnJva2VuIGJ5IHJlcGxhY2luZyBub24tQVNDSUkgYnkgbm90aGluZ1xuICAgICAgICAgICAgICBuZXdwYXJ0ICs9ICd4JztcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIG5ld3BhcnQgKz0gcGFydFtqXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICAgLy8gd2UgdGVzdCBhZ2FpbiB3aXRoIEFTQ0lJIGNoYXIgb25seVxuICAgICAgICAgIGlmICghbmV3cGFydC5tYXRjaChob3N0bmFtZVBhcnRQYXR0ZXJuKSkge1xuICAgICAgICAgICAgdmFyIHZhbGlkUGFydHMgPSBob3N0cGFydHMuc2xpY2UoMCwgaSk7XG4gICAgICAgICAgICB2YXIgbm90SG9zdCA9IGhvc3RwYXJ0cy5zbGljZShpICsgMSk7XG4gICAgICAgICAgICB2YXIgYml0ID0gcGFydC5tYXRjaChob3N0bmFtZVBhcnRTdGFydCk7XG4gICAgICAgICAgICBpZiAoYml0KSB7XG4gICAgICAgICAgICAgIHZhbGlkUGFydHMucHVzaChiaXRbMV0pO1xuICAgICAgICAgICAgICBub3RIb3N0LnVuc2hpZnQoYml0WzJdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChub3RIb3N0Lmxlbmd0aCkge1xuICAgICAgICAgICAgICByZXN0ID0gJy8nICsgbm90SG9zdC5qb2luKCcuJykgKyByZXN0O1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdGhpcy5ob3N0bmFtZSA9IHZhbGlkUGFydHMuam9pbignLicpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuaG9zdG5hbWUubGVuZ3RoID4gaG9zdG5hbWVNYXhMZW4pIHtcbiAgICAgIHRoaXMuaG9zdG5hbWUgPSAnJztcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gaG9zdG5hbWVzIGFyZSBhbHdheXMgbG93ZXIgY2FzZS5cbiAgICAgIHRoaXMuaG9zdG5hbWUgPSB0aGlzLmhvc3RuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgfVxuXG4gICAgaWYgKCFpcHY2SG9zdG5hbWUpIHtcbiAgICAgIC8vIElETkEgU3VwcG9ydDogUmV0dXJucyBhIHB1bnljb2RlZCByZXByZXNlbnRhdGlvbiBvZiBcImRvbWFpblwiLlxuICAgICAgLy8gSXQgb25seSBjb252ZXJ0cyBwYXJ0cyBvZiB0aGUgZG9tYWluIG5hbWUgdGhhdFxuICAgICAgLy8gaGF2ZSBub24tQVNDSUkgY2hhcmFjdGVycywgaS5lLiBpdCBkb2Vzbid0IG1hdHRlciBpZlxuICAgICAgLy8geW91IGNhbGwgaXQgd2l0aCBhIGRvbWFpbiB0aGF0IGFscmVhZHkgaXMgQVNDSUktb25seS5cbiAgICAgIHRoaXMuaG9zdG5hbWUgPSBwdW55Y29kZS50b0FTQ0lJKHRoaXMuaG9zdG5hbWUpO1xuICAgIH1cblxuICAgIHZhciBwID0gdGhpcy5wb3J0ID8gJzonICsgdGhpcy5wb3J0IDogJyc7XG4gICAgdmFyIGggPSB0aGlzLmhvc3RuYW1lIHx8ICcnO1xuICAgIHRoaXMuaG9zdCA9IGggKyBwO1xuICAgIHRoaXMuaHJlZiArPSB0aGlzLmhvc3Q7XG5cbiAgICAvLyBzdHJpcCBbIGFuZCBdIGZyb20gdGhlIGhvc3RuYW1lXG4gICAgLy8gdGhlIGhvc3QgZmllbGQgc3RpbGwgcmV0YWlucyB0aGVtLCB0aG91Z2hcbiAgICBpZiAoaXB2Nkhvc3RuYW1lKSB7XG4gICAgICB0aGlzLmhvc3RuYW1lID0gdGhpcy5ob3N0bmFtZS5zdWJzdHIoMSwgdGhpcy5ob3N0bmFtZS5sZW5ndGggLSAyKTtcbiAgICAgIGlmIChyZXN0WzBdICE9PSAnLycpIHtcbiAgICAgICAgcmVzdCA9ICcvJyArIHJlc3Q7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgLy8gbm93IHJlc3QgaXMgc2V0IHRvIHRoZSBwb3N0LWhvc3Qgc3R1ZmYuXG4gIC8vIGNob3Agb2ZmIGFueSBkZWxpbSBjaGFycy5cbiAgaWYgKCF1bnNhZmVQcm90b2NvbFtsb3dlclByb3RvXSkge1xuXG4gICAgLy8gRmlyc3QsIG1ha2UgMTAwJSBzdXJlIHRoYXQgYW55IFwiYXV0b0VzY2FwZVwiIGNoYXJzIGdldFxuICAgIC8vIGVzY2FwZWQsIGV2ZW4gaWYgZW5jb2RlVVJJQ29tcG9uZW50IGRvZXNuJ3QgdGhpbmsgdGhleVxuICAgIC8vIG5lZWQgdG8gYmUuXG4gICAgZm9yICh2YXIgaSA9IDAsIGwgPSBhdXRvRXNjYXBlLmxlbmd0aDsgaSA8IGw7IGkrKykge1xuICAgICAgdmFyIGFlID0gYXV0b0VzY2FwZVtpXTtcbiAgICAgIGlmIChyZXN0LmluZGV4T2YoYWUpID09PSAtMSlcbiAgICAgICAgY29udGludWU7XG4gICAgICB2YXIgZXNjID0gZW5jb2RlVVJJQ29tcG9uZW50KGFlKTtcbiAgICAgIGlmIChlc2MgPT09IGFlKSB7XG4gICAgICAgIGVzYyA9IGVzY2FwZShhZSk7XG4gICAgICB9XG4gICAgICByZXN0ID0gcmVzdC5zcGxpdChhZSkuam9pbihlc2MpO1xuICAgIH1cbiAgfVxuXG5cbiAgLy8gY2hvcCBvZmYgZnJvbSB0aGUgdGFpbCBmaXJzdC5cbiAgdmFyIGhhc2ggPSByZXN0LmluZGV4T2YoJyMnKTtcbiAgaWYgKGhhc2ggIT09IC0xKSB7XG4gICAgLy8gZ290IGEgZnJhZ21lbnQgc3RyaW5nLlxuICAgIHRoaXMuaGFzaCA9IHJlc3Quc3Vic3RyKGhhc2gpO1xuICAgIHJlc3QgPSByZXN0LnNsaWNlKDAsIGhhc2gpO1xuICB9XG4gIHZhciBxbSA9IHJlc3QuaW5kZXhPZignPycpO1xuICBpZiAocW0gIT09IC0xKSB7XG4gICAgdGhpcy5zZWFyY2ggPSByZXN0LnN1YnN0cihxbSk7XG4gICAgdGhpcy5xdWVyeSA9IHJlc3Quc3Vic3RyKHFtICsgMSk7XG4gICAgaWYgKHBhcnNlUXVlcnlTdHJpbmcpIHtcbiAgICAgIHRoaXMucXVlcnkgPSBxdWVyeXN0cmluZy5wYXJzZSh0aGlzLnF1ZXJ5KTtcbiAgICB9XG4gICAgcmVzdCA9IHJlc3Quc2xpY2UoMCwgcW0pO1xuICB9IGVsc2UgaWYgKHBhcnNlUXVlcnlTdHJpbmcpIHtcbiAgICAvLyBubyBxdWVyeSBzdHJpbmcsIGJ1dCBwYXJzZVF1ZXJ5U3RyaW5nIHN0aWxsIHJlcXVlc3RlZFxuICAgIHRoaXMuc2VhcmNoID0gJyc7XG4gICAgdGhpcy5xdWVyeSA9IHt9O1xuICB9XG4gIGlmIChyZXN0KSB0aGlzLnBhdGhuYW1lID0gcmVzdDtcbiAgaWYgKHNsYXNoZWRQcm90b2NvbFtsb3dlclByb3RvXSAmJlxuICAgICAgdGhpcy5ob3N0bmFtZSAmJiAhdGhpcy5wYXRobmFtZSkge1xuICAgIHRoaXMucGF0aG5hbWUgPSAnLyc7XG4gIH1cblxuICAvL3RvIHN1cHBvcnQgaHR0cC5yZXF1ZXN0XG4gIGlmICh0aGlzLnBhdGhuYW1lIHx8IHRoaXMuc2VhcmNoKSB7XG4gICAgdmFyIHAgPSB0aGlzLnBhdGhuYW1lIHx8ICcnO1xuICAgIHZhciBzID0gdGhpcy5zZWFyY2ggfHwgJyc7XG4gICAgdGhpcy5wYXRoID0gcCArIHM7XG4gIH1cblxuICAvLyBmaW5hbGx5LCByZWNvbnN0cnVjdCB0aGUgaHJlZiBiYXNlZCBvbiB3aGF0IGhhcyBiZWVuIHZhbGlkYXRlZC5cbiAgdGhpcy5ocmVmID0gdGhpcy5mb3JtYXQoKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vLyBmb3JtYXQgYSBwYXJzZWQgb2JqZWN0IGludG8gYSB1cmwgc3RyaW5nXG5mdW5jdGlvbiB1cmxGb3JtYXQob2JqKSB7XG4gIC8vIGVuc3VyZSBpdCdzIGFuIG9iamVjdCwgYW5kIG5vdCBhIHN0cmluZyB1cmwuXG4gIC8vIElmIGl0J3MgYW4gb2JqLCB0aGlzIGlzIGEgbm8tb3AuXG4gIC8vIHRoaXMgd2F5LCB5b3UgY2FuIGNhbGwgdXJsX2Zvcm1hdCgpIG9uIHN0cmluZ3NcbiAgLy8gdG8gY2xlYW4gdXAgcG90ZW50aWFsbHkgd29ua3kgdXJscy5cbiAgaWYgKHV0aWwuaXNTdHJpbmcob2JqKSkgb2JqID0gdXJsUGFyc2Uob2JqKTtcbiAgaWYgKCEob2JqIGluc3RhbmNlb2YgVXJsKSkgcmV0dXJuIFVybC5wcm90b3R5cGUuZm9ybWF0LmNhbGwob2JqKTtcbiAgcmV0dXJuIG9iai5mb3JtYXQoKTtcbn1cblxuVXJsLnByb3RvdHlwZS5mb3JtYXQgPSBmdW5jdGlvbigpIHtcbiAgdmFyIGF1dGggPSB0aGlzLmF1dGggfHwgJyc7XG4gIGlmIChhdXRoKSB7XG4gICAgYXV0aCA9IGVuY29kZVVSSUNvbXBvbmVudChhdXRoKTtcbiAgICBhdXRoID0gYXV0aC5yZXBsYWNlKC8lM0EvaSwgJzonKTtcbiAgICBhdXRoICs9ICdAJztcbiAgfVxuXG4gIHZhciBwcm90b2NvbCA9IHRoaXMucHJvdG9jb2wgfHwgJycsXG4gICAgICBwYXRobmFtZSA9IHRoaXMucGF0aG5hbWUgfHwgJycsXG4gICAgICBoYXNoID0gdGhpcy5oYXNoIHx8ICcnLFxuICAgICAgaG9zdCA9IGZhbHNlLFxuICAgICAgcXVlcnkgPSAnJztcblxuICBpZiAodGhpcy5ob3N0KSB7XG4gICAgaG9zdCA9IGF1dGggKyB0aGlzLmhvc3Q7XG4gIH0gZWxzZSBpZiAodGhpcy5ob3N0bmFtZSkge1xuICAgIGhvc3QgPSBhdXRoICsgKHRoaXMuaG9zdG5hbWUuaW5kZXhPZignOicpID09PSAtMSA/XG4gICAgICAgIHRoaXMuaG9zdG5hbWUgOlxuICAgICAgICAnWycgKyB0aGlzLmhvc3RuYW1lICsgJ10nKTtcbiAgICBpZiAodGhpcy5wb3J0KSB7XG4gICAgICBob3N0ICs9ICc6JyArIHRoaXMucG9ydDtcbiAgICB9XG4gIH1cblxuICBpZiAodGhpcy5xdWVyeSAmJlxuICAgICAgdXRpbC5pc09iamVjdCh0aGlzLnF1ZXJ5KSAmJlxuICAgICAgT2JqZWN0LmtleXModGhpcy5xdWVyeSkubGVuZ3RoKSB7XG4gICAgcXVlcnkgPSBxdWVyeXN0cmluZy5zdHJpbmdpZnkodGhpcy5xdWVyeSk7XG4gIH1cblxuICB2YXIgc2VhcmNoID0gdGhpcy5zZWFyY2ggfHwgKHF1ZXJ5ICYmICgnPycgKyBxdWVyeSkpIHx8ICcnO1xuXG4gIGlmIChwcm90b2NvbCAmJiBwcm90b2NvbC5zdWJzdHIoLTEpICE9PSAnOicpIHByb3RvY29sICs9ICc6JztcblxuICAvLyBvbmx5IHRoZSBzbGFzaGVkUHJvdG9jb2xzIGdldCB0aGUgLy8uICBOb3QgbWFpbHRvOiwgeG1wcDosIGV0Yy5cbiAgLy8gdW5sZXNzIHRoZXkgaGFkIHRoZW0gdG8gYmVnaW4gd2l0aC5cbiAgaWYgKHRoaXMuc2xhc2hlcyB8fFxuICAgICAgKCFwcm90b2NvbCB8fCBzbGFzaGVkUHJvdG9jb2xbcHJvdG9jb2xdKSAmJiBob3N0ICE9PSBmYWxzZSkge1xuICAgIGhvc3QgPSAnLy8nICsgKGhvc3QgfHwgJycpO1xuICAgIGlmIChwYXRobmFtZSAmJiBwYXRobmFtZS5jaGFyQXQoMCkgIT09ICcvJykgcGF0aG5hbWUgPSAnLycgKyBwYXRobmFtZTtcbiAgfSBlbHNlIGlmICghaG9zdCkge1xuICAgIGhvc3QgPSAnJztcbiAgfVxuXG4gIGlmIChoYXNoICYmIGhhc2guY2hhckF0KDApICE9PSAnIycpIGhhc2ggPSAnIycgKyBoYXNoO1xuICBpZiAoc2VhcmNoICYmIHNlYXJjaC5jaGFyQXQoMCkgIT09ICc/Jykgc2VhcmNoID0gJz8nICsgc2VhcmNoO1xuXG4gIHBhdGhuYW1lID0gcGF0aG5hbWUucmVwbGFjZSgvWz8jXS9nLCBmdW5jdGlvbihtYXRjaCkge1xuICAgIHJldHVybiBlbmNvZGVVUklDb21wb25lbnQobWF0Y2gpO1xuICB9KTtcbiAgc2VhcmNoID0gc2VhcmNoLnJlcGxhY2UoJyMnLCAnJTIzJyk7XG5cbiAgcmV0dXJuIHByb3RvY29sICsgaG9zdCArIHBhdGhuYW1lICsgc2VhcmNoICsgaGFzaDtcbn07XG5cbmZ1bmN0aW9uIHVybFJlc29sdmUoc291cmNlLCByZWxhdGl2ZSkge1xuICByZXR1cm4gdXJsUGFyc2Uoc291cmNlLCBmYWxzZSwgdHJ1ZSkucmVzb2x2ZShyZWxhdGl2ZSk7XG59XG5cblVybC5wcm90b3R5cGUucmVzb2x2ZSA9IGZ1bmN0aW9uKHJlbGF0aXZlKSB7XG4gIHJldHVybiB0aGlzLnJlc29sdmVPYmplY3QodXJsUGFyc2UocmVsYXRpdmUsIGZhbHNlLCB0cnVlKSkuZm9ybWF0KCk7XG59O1xuXG5mdW5jdGlvbiB1cmxSZXNvbHZlT2JqZWN0KHNvdXJjZSwgcmVsYXRpdmUpIHtcbiAgaWYgKCFzb3VyY2UpIHJldHVybiByZWxhdGl2ZTtcbiAgcmV0dXJuIHVybFBhcnNlKHNvdXJjZSwgZmFsc2UsIHRydWUpLnJlc29sdmVPYmplY3QocmVsYXRpdmUpO1xufVxuXG5VcmwucHJvdG90eXBlLnJlc29sdmVPYmplY3QgPSBmdW5jdGlvbihyZWxhdGl2ZSkge1xuICBpZiAodXRpbC5pc1N0cmluZyhyZWxhdGl2ZSkpIHtcbiAgICB2YXIgcmVsID0gbmV3IFVybCgpO1xuICAgIHJlbC5wYXJzZShyZWxhdGl2ZSwgZmFsc2UsIHRydWUpO1xuICAgIHJlbGF0aXZlID0gcmVsO1xuICB9XG5cbiAgdmFyIHJlc3VsdCA9IG5ldyBVcmwoKTtcbiAgdmFyIHRrZXlzID0gT2JqZWN0LmtleXModGhpcyk7XG4gIGZvciAodmFyIHRrID0gMDsgdGsgPCB0a2V5cy5sZW5ndGg7IHRrKyspIHtcbiAgICB2YXIgdGtleSA9IHRrZXlzW3RrXTtcbiAgICByZXN1bHRbdGtleV0gPSB0aGlzW3RrZXldO1xuICB9XG5cbiAgLy8gaGFzaCBpcyBhbHdheXMgb3ZlcnJpZGRlbiwgbm8gbWF0dGVyIHdoYXQuXG4gIC8vIGV2ZW4gaHJlZj1cIlwiIHdpbGwgcmVtb3ZlIGl0LlxuICByZXN1bHQuaGFzaCA9IHJlbGF0aXZlLmhhc2g7XG5cbiAgLy8gaWYgdGhlIHJlbGF0aXZlIHVybCBpcyBlbXB0eSwgdGhlbiB0aGVyZSdzIG5vdGhpbmcgbGVmdCB0byBkbyBoZXJlLlxuICBpZiAocmVsYXRpdmUuaHJlZiA9PT0gJycpIHtcbiAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLy8gaHJlZnMgbGlrZSAvL2Zvby9iYXIgYWx3YXlzIGN1dCB0byB0aGUgcHJvdG9jb2wuXG4gIGlmIChyZWxhdGl2ZS5zbGFzaGVzICYmICFyZWxhdGl2ZS5wcm90b2NvbCkge1xuICAgIC8vIHRha2UgZXZlcnl0aGluZyBleGNlcHQgdGhlIHByb3RvY29sIGZyb20gcmVsYXRpdmVcbiAgICB2YXIgcmtleXMgPSBPYmplY3Qua2V5cyhyZWxhdGl2ZSk7XG4gICAgZm9yICh2YXIgcmsgPSAwOyByayA8IHJrZXlzLmxlbmd0aDsgcmsrKykge1xuICAgICAgdmFyIHJrZXkgPSBya2V5c1tya107XG4gICAgICBpZiAocmtleSAhPT0gJ3Byb3RvY29sJylcbiAgICAgICAgcmVzdWx0W3JrZXldID0gcmVsYXRpdmVbcmtleV07XG4gICAgfVxuXG4gICAgLy91cmxQYXJzZSBhcHBlbmRzIHRyYWlsaW5nIC8gdG8gdXJscyBsaWtlIGh0dHA6Ly93d3cuZXhhbXBsZS5jb21cbiAgICBpZiAoc2xhc2hlZFByb3RvY29sW3Jlc3VsdC5wcm90b2NvbF0gJiZcbiAgICAgICAgcmVzdWx0Lmhvc3RuYW1lICYmICFyZXN1bHQucGF0aG5hbWUpIHtcbiAgICAgIHJlc3VsdC5wYXRoID0gcmVzdWx0LnBhdGhuYW1lID0gJy8nO1xuICAgIH1cblxuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICBpZiAocmVsYXRpdmUucHJvdG9jb2wgJiYgcmVsYXRpdmUucHJvdG9jb2wgIT09IHJlc3VsdC5wcm90b2NvbCkge1xuICAgIC8vIGlmIGl0J3MgYSBrbm93biB1cmwgcHJvdG9jb2wsIHRoZW4gY2hhbmdpbmdcbiAgICAvLyB0aGUgcHJvdG9jb2wgZG9lcyB3ZWlyZCB0aGluZ3NcbiAgICAvLyBmaXJzdCwgaWYgaXQncyBub3QgZmlsZTosIHRoZW4gd2UgTVVTVCBoYXZlIGEgaG9zdCxcbiAgICAvLyBhbmQgaWYgdGhlcmUgd2FzIGEgcGF0aFxuICAgIC8vIHRvIGJlZ2luIHdpdGgsIHRoZW4gd2UgTVVTVCBoYXZlIGEgcGF0aC5cbiAgICAvLyBpZiBpdCBpcyBmaWxlOiwgdGhlbiB0aGUgaG9zdCBpcyBkcm9wcGVkLFxuICAgIC8vIGJlY2F1c2UgdGhhdCdzIGtub3duIHRvIGJlIGhvc3RsZXNzLlxuICAgIC8vIGFueXRoaW5nIGVsc2UgaXMgYXNzdW1lZCB0byBiZSBhYnNvbHV0ZS5cbiAgICBpZiAoIXNsYXNoZWRQcm90b2NvbFtyZWxhdGl2ZS5wcm90b2NvbF0pIHtcbiAgICAgIHZhciBrZXlzID0gT2JqZWN0LmtleXMocmVsYXRpdmUpO1xuICAgICAgZm9yICh2YXIgdiA9IDA7IHYgPCBrZXlzLmxlbmd0aDsgdisrKSB7XG4gICAgICAgIHZhciBrID0ga2V5c1t2XTtcbiAgICAgICAgcmVzdWx0W2tdID0gcmVsYXRpdmVba107XG4gICAgICB9XG4gICAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgfVxuXG4gICAgcmVzdWx0LnByb3RvY29sID0gcmVsYXRpdmUucHJvdG9jb2w7XG4gICAgaWYgKCFyZWxhdGl2ZS5ob3N0ICYmICFob3N0bGVzc1Byb3RvY29sW3JlbGF0aXZlLnByb3RvY29sXSkge1xuICAgICAgdmFyIHJlbFBhdGggPSAocmVsYXRpdmUucGF0aG5hbWUgfHwgJycpLnNwbGl0KCcvJyk7XG4gICAgICB3aGlsZSAocmVsUGF0aC5sZW5ndGggJiYgIShyZWxhdGl2ZS5ob3N0ID0gcmVsUGF0aC5zaGlmdCgpKSk7XG4gICAgICBpZiAoIXJlbGF0aXZlLmhvc3QpIHJlbGF0aXZlLmhvc3QgPSAnJztcbiAgICAgIGlmICghcmVsYXRpdmUuaG9zdG5hbWUpIHJlbGF0aXZlLmhvc3RuYW1lID0gJyc7XG4gICAgICBpZiAocmVsUGF0aFswXSAhPT0gJycpIHJlbFBhdGgudW5zaGlmdCgnJyk7XG4gICAgICBpZiAocmVsUGF0aC5sZW5ndGggPCAyKSByZWxQYXRoLnVuc2hpZnQoJycpO1xuICAgICAgcmVzdWx0LnBhdGhuYW1lID0gcmVsUGF0aC5qb2luKCcvJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlc3VsdC5wYXRobmFtZSA9IHJlbGF0aXZlLnBhdGhuYW1lO1xuICAgIH1cbiAgICByZXN1bHQuc2VhcmNoID0gcmVsYXRpdmUuc2VhcmNoO1xuICAgIHJlc3VsdC5xdWVyeSA9IHJlbGF0aXZlLnF1ZXJ5O1xuICAgIHJlc3VsdC5ob3N0ID0gcmVsYXRpdmUuaG9zdCB8fCAnJztcbiAgICByZXN1bHQuYXV0aCA9IHJlbGF0aXZlLmF1dGg7XG4gICAgcmVzdWx0Lmhvc3RuYW1lID0gcmVsYXRpdmUuaG9zdG5hbWUgfHwgcmVsYXRpdmUuaG9zdDtcbiAgICByZXN1bHQucG9ydCA9IHJlbGF0aXZlLnBvcnQ7XG4gICAgLy8gdG8gc3VwcG9ydCBodHRwLnJlcXVlc3RcbiAgICBpZiAocmVzdWx0LnBhdGhuYW1lIHx8IHJlc3VsdC5zZWFyY2gpIHtcbiAgICAgIHZhciBwID0gcmVzdWx0LnBhdGhuYW1lIHx8ICcnO1xuICAgICAgdmFyIHMgPSByZXN1bHQuc2VhcmNoIHx8ICcnO1xuICAgICAgcmVzdWx0LnBhdGggPSBwICsgcztcbiAgICB9XG4gICAgcmVzdWx0LnNsYXNoZXMgPSByZXN1bHQuc2xhc2hlcyB8fCByZWxhdGl2ZS5zbGFzaGVzO1xuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICB2YXIgaXNTb3VyY2VBYnMgPSAocmVzdWx0LnBhdGhuYW1lICYmIHJlc3VsdC5wYXRobmFtZS5jaGFyQXQoMCkgPT09ICcvJyksXG4gICAgICBpc1JlbEFicyA9IChcbiAgICAgICAgICByZWxhdGl2ZS5ob3N0IHx8XG4gICAgICAgICAgcmVsYXRpdmUucGF0aG5hbWUgJiYgcmVsYXRpdmUucGF0aG5hbWUuY2hhckF0KDApID09PSAnLydcbiAgICAgICksXG4gICAgICBtdXN0RW5kQWJzID0gKGlzUmVsQWJzIHx8IGlzU291cmNlQWJzIHx8XG4gICAgICAgICAgICAgICAgICAgIChyZXN1bHQuaG9zdCAmJiByZWxhdGl2ZS5wYXRobmFtZSkpLFxuICAgICAgcmVtb3ZlQWxsRG90cyA9IG11c3RFbmRBYnMsXG4gICAgICBzcmNQYXRoID0gcmVzdWx0LnBhdGhuYW1lICYmIHJlc3VsdC5wYXRobmFtZS5zcGxpdCgnLycpIHx8IFtdLFxuICAgICAgcmVsUGF0aCA9IHJlbGF0aXZlLnBhdGhuYW1lICYmIHJlbGF0aXZlLnBhdGhuYW1lLnNwbGl0KCcvJykgfHwgW10sXG4gICAgICBwc3ljaG90aWMgPSByZXN1bHQucHJvdG9jb2wgJiYgIXNsYXNoZWRQcm90b2NvbFtyZXN1bHQucHJvdG9jb2xdO1xuXG4gIC8vIGlmIHRoZSB1cmwgaXMgYSBub24tc2xhc2hlZCB1cmwsIHRoZW4gcmVsYXRpdmVcbiAgLy8gbGlua3MgbGlrZSAuLi8uLiBzaG91bGQgYmUgYWJsZVxuICAvLyB0byBjcmF3bCB1cCB0byB0aGUgaG9zdG5hbWUsIGFzIHdlbGwuICBUaGlzIGlzIHN0cmFuZ2UuXG4gIC8vIHJlc3VsdC5wcm90b2NvbCBoYXMgYWxyZWFkeSBiZWVuIHNldCBieSBub3cuXG4gIC8vIExhdGVyIG9uLCBwdXQgdGhlIGZpcnN0IHBhdGggcGFydCBpbnRvIHRoZSBob3N0IGZpZWxkLlxuICBpZiAocHN5Y2hvdGljKSB7XG4gICAgcmVzdWx0Lmhvc3RuYW1lID0gJyc7XG4gICAgcmVzdWx0LnBvcnQgPSBudWxsO1xuICAgIGlmIChyZXN1bHQuaG9zdCkge1xuICAgICAgaWYgKHNyY1BhdGhbMF0gPT09ICcnKSBzcmNQYXRoWzBdID0gcmVzdWx0Lmhvc3Q7XG4gICAgICBlbHNlIHNyY1BhdGgudW5zaGlmdChyZXN1bHQuaG9zdCk7XG4gICAgfVxuICAgIHJlc3VsdC5ob3N0ID0gJyc7XG4gICAgaWYgKHJlbGF0aXZlLnByb3RvY29sKSB7XG4gICAgICByZWxhdGl2ZS5ob3N0bmFtZSA9IG51bGw7XG4gICAgICByZWxhdGl2ZS5wb3J0ID0gbnVsbDtcbiAgICAgIGlmIChyZWxhdGl2ZS5ob3N0KSB7XG4gICAgICAgIGlmIChyZWxQYXRoWzBdID09PSAnJykgcmVsUGF0aFswXSA9IHJlbGF0aXZlLmhvc3Q7XG4gICAgICAgIGVsc2UgcmVsUGF0aC51bnNoaWZ0KHJlbGF0aXZlLmhvc3QpO1xuICAgICAgfVxuICAgICAgcmVsYXRpdmUuaG9zdCA9IG51bGw7XG4gICAgfVxuICAgIG11c3RFbmRBYnMgPSBtdXN0RW5kQWJzICYmIChyZWxQYXRoWzBdID09PSAnJyB8fCBzcmNQYXRoWzBdID09PSAnJyk7XG4gIH1cblxuICBpZiAoaXNSZWxBYnMpIHtcbiAgICAvLyBpdCdzIGFic29sdXRlLlxuICAgIHJlc3VsdC5ob3N0ID0gKHJlbGF0aXZlLmhvc3QgfHwgcmVsYXRpdmUuaG9zdCA9PT0gJycpID9cbiAgICAgICAgICAgICAgICAgIHJlbGF0aXZlLmhvc3QgOiByZXN1bHQuaG9zdDtcbiAgICByZXN1bHQuaG9zdG5hbWUgPSAocmVsYXRpdmUuaG9zdG5hbWUgfHwgcmVsYXRpdmUuaG9zdG5hbWUgPT09ICcnKSA/XG4gICAgICAgICAgICAgICAgICAgICAgcmVsYXRpdmUuaG9zdG5hbWUgOiByZXN1bHQuaG9zdG5hbWU7XG4gICAgcmVzdWx0LnNlYXJjaCA9IHJlbGF0aXZlLnNlYXJjaDtcbiAgICByZXN1bHQucXVlcnkgPSByZWxhdGl2ZS5xdWVyeTtcbiAgICBzcmNQYXRoID0gcmVsUGF0aDtcbiAgICAvLyBmYWxsIHRocm91Z2ggdG8gdGhlIGRvdC1oYW5kbGluZyBiZWxvdy5cbiAgfSBlbHNlIGlmIChyZWxQYXRoLmxlbmd0aCkge1xuICAgIC8vIGl0J3MgcmVsYXRpdmVcbiAgICAvLyB0aHJvdyBhd2F5IHRoZSBleGlzdGluZyBmaWxlLCBhbmQgdGFrZSB0aGUgbmV3IHBhdGggaW5zdGVhZC5cbiAgICBpZiAoIXNyY1BhdGgpIHNyY1BhdGggPSBbXTtcbiAgICBzcmNQYXRoLnBvcCgpO1xuICAgIHNyY1BhdGggPSBzcmNQYXRoLmNvbmNhdChyZWxQYXRoKTtcbiAgICByZXN1bHQuc2VhcmNoID0gcmVsYXRpdmUuc2VhcmNoO1xuICAgIHJlc3VsdC5xdWVyeSA9IHJlbGF0aXZlLnF1ZXJ5O1xuICB9IGVsc2UgaWYgKCF1dGlsLmlzTnVsbE9yVW5kZWZpbmVkKHJlbGF0aXZlLnNlYXJjaCkpIHtcbiAgICAvLyBqdXN0IHB1bGwgb3V0IHRoZSBzZWFyY2guXG4gICAgLy8gbGlrZSBocmVmPSc/Zm9vJy5cbiAgICAvLyBQdXQgdGhpcyBhZnRlciB0aGUgb3RoZXIgdHdvIGNhc2VzIGJlY2F1c2UgaXQgc2ltcGxpZmllcyB0aGUgYm9vbGVhbnNcbiAgICBpZiAocHN5Y2hvdGljKSB7XG4gICAgICByZXN1bHQuaG9zdG5hbWUgPSByZXN1bHQuaG9zdCA9IHNyY1BhdGguc2hpZnQoKTtcbiAgICAgIC8vb2NjYXRpb25hbHkgdGhlIGF1dGggY2FuIGdldCBzdHVjayBvbmx5IGluIGhvc3RcbiAgICAgIC8vdGhpcyBlc3BlY2lhbGx5IGhhcHBlbnMgaW4gY2FzZXMgbGlrZVxuICAgICAgLy91cmwucmVzb2x2ZU9iamVjdCgnbWFpbHRvOmxvY2FsMUBkb21haW4xJywgJ2xvY2FsMkBkb21haW4yJylcbiAgICAgIHZhciBhdXRoSW5Ib3N0ID0gcmVzdWx0Lmhvc3QgJiYgcmVzdWx0Lmhvc3QuaW5kZXhPZignQCcpID4gMCA/XG4gICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5ob3N0LnNwbGl0KCdAJykgOiBmYWxzZTtcbiAgICAgIGlmIChhdXRoSW5Ib3N0KSB7XG4gICAgICAgIHJlc3VsdC5hdXRoID0gYXV0aEluSG9zdC5zaGlmdCgpO1xuICAgICAgICByZXN1bHQuaG9zdCA9IHJlc3VsdC5ob3N0bmFtZSA9IGF1dGhJbkhvc3Quc2hpZnQoKTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmVzdWx0LnNlYXJjaCA9IHJlbGF0aXZlLnNlYXJjaDtcbiAgICByZXN1bHQucXVlcnkgPSByZWxhdGl2ZS5xdWVyeTtcbiAgICAvL3RvIHN1cHBvcnQgaHR0cC5yZXF1ZXN0XG4gICAgaWYgKCF1dGlsLmlzTnVsbChyZXN1bHQucGF0aG5hbWUpIHx8ICF1dGlsLmlzTnVsbChyZXN1bHQuc2VhcmNoKSkge1xuICAgICAgcmVzdWx0LnBhdGggPSAocmVzdWx0LnBhdGhuYW1lID8gcmVzdWx0LnBhdGhuYW1lIDogJycpICtcbiAgICAgICAgICAgICAgICAgICAgKHJlc3VsdC5zZWFyY2ggPyByZXN1bHQuc2VhcmNoIDogJycpO1xuICAgIH1cbiAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgaWYgKCFzcmNQYXRoLmxlbmd0aCkge1xuICAgIC8vIG5vIHBhdGggYXQgYWxsLiAgZWFzeS5cbiAgICAvLyB3ZSd2ZSBhbHJlYWR5IGhhbmRsZWQgdGhlIG90aGVyIHN0dWZmIGFib3ZlLlxuICAgIHJlc3VsdC5wYXRobmFtZSA9IG51bGw7XG4gICAgLy90byBzdXBwb3J0IGh0dHAucmVxdWVzdFxuICAgIGlmIChyZXN1bHQuc2VhcmNoKSB7XG4gICAgICByZXN1bHQucGF0aCA9ICcvJyArIHJlc3VsdC5zZWFyY2g7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlc3VsdC5wYXRoID0gbnVsbDtcbiAgICB9XG4gICAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIC8vIGlmIGEgdXJsIEVORHMgaW4gLiBvciAuLiwgdGhlbiBpdCBtdXN0IGdldCBhIHRyYWlsaW5nIHNsYXNoLlxuICAvLyBob3dldmVyLCBpZiBpdCBlbmRzIGluIGFueXRoaW5nIGVsc2Ugbm9uLXNsYXNoeSxcbiAgLy8gdGhlbiBpdCBtdXN0IE5PVCBnZXQgYSB0cmFpbGluZyBzbGFzaC5cbiAgdmFyIGxhc3QgPSBzcmNQYXRoLnNsaWNlKC0xKVswXTtcbiAgdmFyIGhhc1RyYWlsaW5nU2xhc2ggPSAoXG4gICAgICAocmVzdWx0Lmhvc3QgfHwgcmVsYXRpdmUuaG9zdCB8fCBzcmNQYXRoLmxlbmd0aCA+IDEpICYmXG4gICAgICAobGFzdCA9PT0gJy4nIHx8IGxhc3QgPT09ICcuLicpIHx8IGxhc3QgPT09ICcnKTtcblxuICAvLyBzdHJpcCBzaW5nbGUgZG90cywgcmVzb2x2ZSBkb3VibGUgZG90cyB0byBwYXJlbnQgZGlyXG4gIC8vIGlmIHRoZSBwYXRoIHRyaWVzIHRvIGdvIGFib3ZlIHRoZSByb290LCBgdXBgIGVuZHMgdXAgPiAwXG4gIHZhciB1cCA9IDA7XG4gIGZvciAodmFyIGkgPSBzcmNQYXRoLmxlbmd0aDsgaSA+PSAwOyBpLS0pIHtcbiAgICBsYXN0ID0gc3JjUGF0aFtpXTtcbiAgICBpZiAobGFzdCA9PT0gJy4nKSB7XG4gICAgICBzcmNQYXRoLnNwbGljZShpLCAxKTtcbiAgICB9IGVsc2UgaWYgKGxhc3QgPT09ICcuLicpIHtcbiAgICAgIHNyY1BhdGguc3BsaWNlKGksIDEpO1xuICAgICAgdXArKztcbiAgICB9IGVsc2UgaWYgKHVwKSB7XG4gICAgICBzcmNQYXRoLnNwbGljZShpLCAxKTtcbiAgICAgIHVwLS07XG4gICAgfVxuICB9XG5cbiAgLy8gaWYgdGhlIHBhdGggaXMgYWxsb3dlZCB0byBnbyBhYm92ZSB0aGUgcm9vdCwgcmVzdG9yZSBsZWFkaW5nIC4uc1xuICBpZiAoIW11c3RFbmRBYnMgJiYgIXJlbW92ZUFsbERvdHMpIHtcbiAgICBmb3IgKDsgdXAtLTsgdXApIHtcbiAgICAgIHNyY1BhdGgudW5zaGlmdCgnLi4nKTtcbiAgICB9XG4gIH1cblxuICBpZiAobXVzdEVuZEFicyAmJiBzcmNQYXRoWzBdICE9PSAnJyAmJlxuICAgICAgKCFzcmNQYXRoWzBdIHx8IHNyY1BhdGhbMF0uY2hhckF0KDApICE9PSAnLycpKSB7XG4gICAgc3JjUGF0aC51bnNoaWZ0KCcnKTtcbiAgfVxuXG4gIGlmIChoYXNUcmFpbGluZ1NsYXNoICYmIChzcmNQYXRoLmpvaW4oJy8nKS5zdWJzdHIoLTEpICE9PSAnLycpKSB7XG4gICAgc3JjUGF0aC5wdXNoKCcnKTtcbiAgfVxuXG4gIHZhciBpc0Fic29sdXRlID0gc3JjUGF0aFswXSA9PT0gJycgfHxcbiAgICAgIChzcmNQYXRoWzBdICYmIHNyY1BhdGhbMF0uY2hhckF0KDApID09PSAnLycpO1xuXG4gIC8vIHB1dCB0aGUgaG9zdCBiYWNrXG4gIGlmIChwc3ljaG90aWMpIHtcbiAgICByZXN1bHQuaG9zdG5hbWUgPSByZXN1bHQuaG9zdCA9IGlzQWJzb2x1dGUgPyAnJyA6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcmNQYXRoLmxlbmd0aCA/IHNyY1BhdGguc2hpZnQoKSA6ICcnO1xuICAgIC8vb2NjYXRpb25hbHkgdGhlIGF1dGggY2FuIGdldCBzdHVjayBvbmx5IGluIGhvc3RcbiAgICAvL3RoaXMgZXNwZWNpYWxseSBoYXBwZW5zIGluIGNhc2VzIGxpa2VcbiAgICAvL3VybC5yZXNvbHZlT2JqZWN0KCdtYWlsdG86bG9jYWwxQGRvbWFpbjEnLCAnbG9jYWwyQGRvbWFpbjInKVxuICAgIHZhciBhdXRoSW5Ib3N0ID0gcmVzdWx0Lmhvc3QgJiYgcmVzdWx0Lmhvc3QuaW5kZXhPZignQCcpID4gMCA/XG4gICAgICAgICAgICAgICAgICAgICByZXN1bHQuaG9zdC5zcGxpdCgnQCcpIDogZmFsc2U7XG4gICAgaWYgKGF1dGhJbkhvc3QpIHtcbiAgICAgIHJlc3VsdC5hdXRoID0gYXV0aEluSG9zdC5zaGlmdCgpO1xuICAgICAgcmVzdWx0Lmhvc3QgPSByZXN1bHQuaG9zdG5hbWUgPSBhdXRoSW5Ib3N0LnNoaWZ0KCk7XG4gICAgfVxuICB9XG5cbiAgbXVzdEVuZEFicyA9IG11c3RFbmRBYnMgfHwgKHJlc3VsdC5ob3N0ICYmIHNyY1BhdGgubGVuZ3RoKTtcblxuICBpZiAobXVzdEVuZEFicyAmJiAhaXNBYnNvbHV0ZSkge1xuICAgIHNyY1BhdGgudW5zaGlmdCgnJyk7XG4gIH1cblxuICBpZiAoIXNyY1BhdGgubGVuZ3RoKSB7XG4gICAgcmVzdWx0LnBhdGhuYW1lID0gbnVsbDtcbiAgICByZXN1bHQucGF0aCA9IG51bGw7XG4gIH0gZWxzZSB7XG4gICAgcmVzdWx0LnBhdGhuYW1lID0gc3JjUGF0aC5qb2luKCcvJyk7XG4gIH1cblxuICAvL3RvIHN1cHBvcnQgcmVxdWVzdC5odHRwXG4gIGlmICghdXRpbC5pc051bGwocmVzdWx0LnBhdGhuYW1lKSB8fCAhdXRpbC5pc051bGwocmVzdWx0LnNlYXJjaCkpIHtcbiAgICByZXN1bHQucGF0aCA9IChyZXN1bHQucGF0aG5hbWUgPyByZXN1bHQucGF0aG5hbWUgOiAnJykgK1xuICAgICAgICAgICAgICAgICAgKHJlc3VsdC5zZWFyY2ggPyByZXN1bHQuc2VhcmNoIDogJycpO1xuICB9XG4gIHJlc3VsdC5hdXRoID0gcmVsYXRpdmUuYXV0aCB8fCByZXN1bHQuYXV0aDtcbiAgcmVzdWx0LnNsYXNoZXMgPSByZXN1bHQuc2xhc2hlcyB8fCByZWxhdGl2ZS5zbGFzaGVzO1xuICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgcmV0dXJuIHJlc3VsdDtcbn07XG5cblVybC5wcm90b3R5cGUucGFyc2VIb3N0ID0gZnVuY3Rpb24oKSB7XG4gIHZhciBob3N0ID0gdGhpcy5ob3N0O1xuICB2YXIgcG9ydCA9IHBvcnRQYXR0ZXJuLmV4ZWMoaG9zdCk7XG4gIGlmIChwb3J0KSB7XG4gICAgcG9ydCA9IHBvcnRbMF07XG4gICAgaWYgKHBvcnQgIT09ICc6Jykge1xuICAgICAgdGhpcy5wb3J0ID0gcG9ydC5zdWJzdHIoMSk7XG4gICAgfVxuICAgIGhvc3QgPSBob3N0LnN1YnN0cigwLCBob3N0Lmxlbmd0aCAtIHBvcnQubGVuZ3RoKTtcbiAgfVxuICBpZiAoaG9zdCkgdGhpcy5ob3N0bmFtZSA9IGhvc3Q7XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgaXNTdHJpbmc6IGZ1bmN0aW9uKGFyZykge1xuICAgIHJldHVybiB0eXBlb2YoYXJnKSA9PT0gJ3N0cmluZyc7XG4gIH0sXG4gIGlzT2JqZWN0OiBmdW5jdGlvbihhcmcpIHtcbiAgICByZXR1cm4gdHlwZW9mKGFyZykgPT09ICdvYmplY3QnICYmIGFyZyAhPT0gbnVsbDtcbiAgfSxcbiAgaXNOdWxsOiBmdW5jdGlvbihhcmcpIHtcbiAgICByZXR1cm4gYXJnID09PSBudWxsO1xuICB9LFxuICBpc051bGxPclVuZGVmaW5lZDogZnVuY3Rpb24oYXJnKSB7XG4gICAgcmV0dXJuIGFyZyA9PSBudWxsO1xuICB9XG59O1xuIiwidmFyIHYxID0gcmVxdWlyZSgnLi92MScpO1xudmFyIHY0ID0gcmVxdWlyZSgnLi92NCcpO1xuXG52YXIgdXVpZCA9IHY0O1xudXVpZC52MSA9IHYxO1xudXVpZC52NCA9IHY0O1xuXG5tb2R1bGUuZXhwb3J0cyA9IHV1aWQ7XG4iLCIvKipcbiAqIENvbnZlcnQgYXJyYXkgb2YgMTYgYnl0ZSB2YWx1ZXMgdG8gVVVJRCBzdHJpbmcgZm9ybWF0IG9mIHRoZSBmb3JtOlxuICogWFhYWFhYWFgtWFhYWC1YWFhYLVhYWFgtWFhYWFhYWFhYWFhYXG4gKi9cbnZhciBieXRlVG9IZXggPSBbXTtcbmZvciAodmFyIGkgPSAwOyBpIDwgMjU2OyArK2kpIHtcbiAgYnl0ZVRvSGV4W2ldID0gKGkgKyAweDEwMCkudG9TdHJpbmcoMTYpLnN1YnN0cigxKTtcbn1cblxuZnVuY3Rpb24gYnl0ZXNUb1V1aWQoYnVmLCBvZmZzZXQpIHtcbiAgdmFyIGkgPSBvZmZzZXQgfHwgMDtcbiAgdmFyIGJ0aCA9IGJ5dGVUb0hleDtcbiAgcmV0dXJuIGJ0aFtidWZbaSsrXV0gKyBidGhbYnVmW2krK11dICtcbiAgICAgICAgICBidGhbYnVmW2krK11dICsgYnRoW2J1ZltpKytdXSArICctJyArXG4gICAgICAgICAgYnRoW2J1ZltpKytdXSArIGJ0aFtidWZbaSsrXV0gKyAnLScgK1xuICAgICAgICAgIGJ0aFtidWZbaSsrXV0gKyBidGhbYnVmW2krK11dICsgJy0nICtcbiAgICAgICAgICBidGhbYnVmW2krK11dICsgYnRoW2J1ZltpKytdXSArICctJyArXG4gICAgICAgICAgYnRoW2J1ZltpKytdXSArIGJ0aFtidWZbaSsrXV0gK1xuICAgICAgICAgIGJ0aFtidWZbaSsrXV0gKyBidGhbYnVmW2krK11dICtcbiAgICAgICAgICBidGhbYnVmW2krK11dICsgYnRoW2J1ZltpKytdXTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBieXRlc1RvVXVpZDtcbiIsIi8vIFVuaXF1ZSBJRCBjcmVhdGlvbiByZXF1aXJlcyBhIGhpZ2ggcXVhbGl0eSByYW5kb20gIyBnZW5lcmF0b3IuICBJbiB0aGVcbi8vIGJyb3dzZXIgdGhpcyBpcyBhIGxpdHRsZSBjb21wbGljYXRlZCBkdWUgdG8gdW5rbm93biBxdWFsaXR5IG9mIE1hdGgucmFuZG9tKClcbi8vIGFuZCBpbmNvbnNpc3RlbnQgc3VwcG9ydCBmb3IgdGhlIGBjcnlwdG9gIEFQSS4gIFdlIGRvIHRoZSBiZXN0IHdlIGNhbiB2aWFcbi8vIGZlYXR1cmUtZGV0ZWN0aW9uXG52YXIgcm5nO1xuXG52YXIgY3J5cHRvID0gZ2xvYmFsLmNyeXB0byB8fCBnbG9iYWwubXNDcnlwdG87IC8vIGZvciBJRSAxMVxuaWYgKGNyeXB0byAmJiBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKSB7XG4gIC8vIFdIQVRXRyBjcnlwdG8gUk5HIC0gaHR0cDovL3dpa2kud2hhdHdnLm9yZy93aWtpL0NyeXB0b1xuICB2YXIgcm5kczggPSBuZXcgVWludDhBcnJheSgxNik7IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbm8tdW5kZWZcbiAgcm5nID0gZnVuY3Rpb24gd2hhdHdnUk5HKCkge1xuICAgIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMocm5kczgpO1xuICAgIHJldHVybiBybmRzODtcbiAgfTtcbn1cblxuaWYgKCFybmcpIHtcbiAgLy8gTWF0aC5yYW5kb20oKS1iYXNlZCAoUk5HKVxuICAvL1xuICAvLyBJZiBhbGwgZWxzZSBmYWlscywgdXNlIE1hdGgucmFuZG9tKCkuICBJdCdzIGZhc3QsIGJ1dCBpcyBvZiB1bnNwZWNpZmllZFxuICAvLyBxdWFsaXR5LlxuICB2YXIgcm5kcyA9IG5ldyBBcnJheSgxNik7XG4gIHJuZyA9IGZ1bmN0aW9uKCkge1xuICAgIGZvciAodmFyIGkgPSAwLCByOyBpIDwgMTY7IGkrKykge1xuICAgICAgaWYgKChpICYgMHgwMykgPT09IDApIHIgPSBNYXRoLnJhbmRvbSgpICogMHgxMDAwMDAwMDA7XG4gICAgICBybmRzW2ldID0gciA+Pj4gKChpICYgMHgwMykgPDwgMykgJiAweGZmO1xuICAgIH1cblxuICAgIHJldHVybiBybmRzO1xuICB9O1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IHJuZztcbiIsInZhciBybmcgPSByZXF1aXJlKCcuL2xpYi9ybmcnKTtcbnZhciBieXRlc1RvVXVpZCA9IHJlcXVpcmUoJy4vbGliL2J5dGVzVG9VdWlkJyk7XG5cbi8vICoqYHYxKClgIC0gR2VuZXJhdGUgdGltZS1iYXNlZCBVVUlEKipcbi8vXG4vLyBJbnNwaXJlZCBieSBodHRwczovL2dpdGh1Yi5jb20vTGlvc0svVVVJRC5qc1xuLy8gYW5kIGh0dHA6Ly9kb2NzLnB5dGhvbi5vcmcvbGlicmFyeS91dWlkLmh0bWxcblxuLy8gcmFuZG9tICMncyB3ZSBuZWVkIHRvIGluaXQgbm9kZSBhbmQgY2xvY2tzZXFcbnZhciBfc2VlZEJ5dGVzID0gcm5nKCk7XG5cbi8vIFBlciA0LjUsIGNyZWF0ZSBhbmQgNDgtYml0IG5vZGUgaWQsICg0NyByYW5kb20gYml0cyArIG11bHRpY2FzdCBiaXQgPSAxKVxudmFyIF9ub2RlSWQgPSBbXG4gIF9zZWVkQnl0ZXNbMF0gfCAweDAxLFxuICBfc2VlZEJ5dGVzWzFdLCBfc2VlZEJ5dGVzWzJdLCBfc2VlZEJ5dGVzWzNdLCBfc2VlZEJ5dGVzWzRdLCBfc2VlZEJ5dGVzWzVdXG5dO1xuXG4vLyBQZXIgNC4yLjIsIHJhbmRvbWl6ZSAoMTQgYml0KSBjbG9ja3NlcVxudmFyIF9jbG9ja3NlcSA9IChfc2VlZEJ5dGVzWzZdIDw8IDggfCBfc2VlZEJ5dGVzWzddKSAmIDB4M2ZmZjtcblxuLy8gUHJldmlvdXMgdXVpZCBjcmVhdGlvbiB0aW1lXG52YXIgX2xhc3RNU2VjcyA9IDAsIF9sYXN0TlNlY3MgPSAwO1xuXG4vLyBTZWUgaHR0cHM6Ly9naXRodWIuY29tL2Jyb29mYS9ub2RlLXV1aWQgZm9yIEFQSSBkZXRhaWxzXG5mdW5jdGlvbiB2MShvcHRpb25zLCBidWYsIG9mZnNldCkge1xuICB2YXIgaSA9IGJ1ZiAmJiBvZmZzZXQgfHwgMDtcbiAgdmFyIGIgPSBidWYgfHwgW107XG5cbiAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG5cbiAgdmFyIGNsb2Nrc2VxID0gb3B0aW9ucy5jbG9ja3NlcSAhPT0gdW5kZWZpbmVkID8gb3B0aW9ucy5jbG9ja3NlcSA6IF9jbG9ja3NlcTtcblxuICAvLyBVVUlEIHRpbWVzdGFtcHMgYXJlIDEwMCBuYW5vLXNlY29uZCB1bml0cyBzaW5jZSB0aGUgR3JlZ29yaWFuIGVwb2NoLFxuICAvLyAoMTU4Mi0xMC0xNSAwMDowMCkuICBKU051bWJlcnMgYXJlbid0IHByZWNpc2UgZW5vdWdoIGZvciB0aGlzLCBzb1xuICAvLyB0aW1lIGlzIGhhbmRsZWQgaW50ZXJuYWxseSBhcyAnbXNlY3MnIChpbnRlZ2VyIG1pbGxpc2Vjb25kcykgYW5kICduc2VjcydcbiAgLy8gKDEwMC1uYW5vc2Vjb25kcyBvZmZzZXQgZnJvbSBtc2Vjcykgc2luY2UgdW5peCBlcG9jaCwgMTk3MC0wMS0wMSAwMDowMC5cbiAgdmFyIG1zZWNzID0gb3B0aW9ucy5tc2VjcyAhPT0gdW5kZWZpbmVkID8gb3B0aW9ucy5tc2VjcyA6IG5ldyBEYXRlKCkuZ2V0VGltZSgpO1xuXG4gIC8vIFBlciA0LjIuMS4yLCB1c2UgY291bnQgb2YgdXVpZCdzIGdlbmVyYXRlZCBkdXJpbmcgdGhlIGN1cnJlbnQgY2xvY2tcbiAgLy8gY3ljbGUgdG8gc2ltdWxhdGUgaGlnaGVyIHJlc29sdXRpb24gY2xvY2tcbiAgdmFyIG5zZWNzID0gb3B0aW9ucy5uc2VjcyAhPT0gdW5kZWZpbmVkID8gb3B0aW9ucy5uc2VjcyA6IF9sYXN0TlNlY3MgKyAxO1xuXG4gIC8vIFRpbWUgc2luY2UgbGFzdCB1dWlkIGNyZWF0aW9uIChpbiBtc2VjcylcbiAgdmFyIGR0ID0gKG1zZWNzIC0gX2xhc3RNU2VjcykgKyAobnNlY3MgLSBfbGFzdE5TZWNzKS8xMDAwMDtcblxuICAvLyBQZXIgNC4yLjEuMiwgQnVtcCBjbG9ja3NlcSBvbiBjbG9jayByZWdyZXNzaW9uXG4gIGlmIChkdCA8IDAgJiYgb3B0aW9ucy5jbG9ja3NlcSA9PT0gdW5kZWZpbmVkKSB7XG4gICAgY2xvY2tzZXEgPSBjbG9ja3NlcSArIDEgJiAweDNmZmY7XG4gIH1cblxuICAvLyBSZXNldCBuc2VjcyBpZiBjbG9jayByZWdyZXNzZXMgKG5ldyBjbG9ja3NlcSkgb3Igd2UndmUgbW92ZWQgb250byBhIG5ld1xuICAvLyB0aW1lIGludGVydmFsXG4gIGlmICgoZHQgPCAwIHx8IG1zZWNzID4gX2xhc3RNU2VjcykgJiYgb3B0aW9ucy5uc2VjcyA9PT0gdW5kZWZpbmVkKSB7XG4gICAgbnNlY3MgPSAwO1xuICB9XG5cbiAgLy8gUGVyIDQuMi4xLjIgVGhyb3cgZXJyb3IgaWYgdG9vIG1hbnkgdXVpZHMgYXJlIHJlcXVlc3RlZFxuICBpZiAobnNlY3MgPj0gMTAwMDApIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ3V1aWQudjEoKTogQ2FuXFwndCBjcmVhdGUgbW9yZSB0aGFuIDEwTSB1dWlkcy9zZWMnKTtcbiAgfVxuXG4gIF9sYXN0TVNlY3MgPSBtc2VjcztcbiAgX2xhc3ROU2VjcyA9IG5zZWNzO1xuICBfY2xvY2tzZXEgPSBjbG9ja3NlcTtcblxuICAvLyBQZXIgNC4xLjQgLSBDb252ZXJ0IGZyb20gdW5peCBlcG9jaCB0byBHcmVnb3JpYW4gZXBvY2hcbiAgbXNlY3MgKz0gMTIyMTkyOTI4MDAwMDA7XG5cbiAgLy8gYHRpbWVfbG93YFxuICB2YXIgdGwgPSAoKG1zZWNzICYgMHhmZmZmZmZmKSAqIDEwMDAwICsgbnNlY3MpICUgMHgxMDAwMDAwMDA7XG4gIGJbaSsrXSA9IHRsID4+PiAyNCAmIDB4ZmY7XG4gIGJbaSsrXSA9IHRsID4+PiAxNiAmIDB4ZmY7XG4gIGJbaSsrXSA9IHRsID4+PiA4ICYgMHhmZjtcbiAgYltpKytdID0gdGwgJiAweGZmO1xuXG4gIC8vIGB0aW1lX21pZGBcbiAgdmFyIHRtaCA9IChtc2VjcyAvIDB4MTAwMDAwMDAwICogMTAwMDApICYgMHhmZmZmZmZmO1xuICBiW2krK10gPSB0bWggPj4+IDggJiAweGZmO1xuICBiW2krK10gPSB0bWggJiAweGZmO1xuXG4gIC8vIGB0aW1lX2hpZ2hfYW5kX3ZlcnNpb25gXG4gIGJbaSsrXSA9IHRtaCA+Pj4gMjQgJiAweGYgfCAweDEwOyAvLyBpbmNsdWRlIHZlcnNpb25cbiAgYltpKytdID0gdG1oID4+PiAxNiAmIDB4ZmY7XG5cbiAgLy8gYGNsb2NrX3NlcV9oaV9hbmRfcmVzZXJ2ZWRgIChQZXIgNC4yLjIgLSBpbmNsdWRlIHZhcmlhbnQpXG4gIGJbaSsrXSA9IGNsb2Nrc2VxID4+PiA4IHwgMHg4MDtcblxuICAvLyBgY2xvY2tfc2VxX2xvd2BcbiAgYltpKytdID0gY2xvY2tzZXEgJiAweGZmO1xuXG4gIC8vIGBub2RlYFxuICB2YXIgbm9kZSA9IG9wdGlvbnMubm9kZSB8fCBfbm9kZUlkO1xuICBmb3IgKHZhciBuID0gMDsgbiA8IDY7ICsrbikge1xuICAgIGJbaSArIG5dID0gbm9kZVtuXTtcbiAgfVxuXG4gIHJldHVybiBidWYgPyBidWYgOiBieXRlc1RvVXVpZChiKTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSB2MTtcbiIsInZhciBybmcgPSByZXF1aXJlKCcuL2xpYi9ybmcnKTtcbnZhciBieXRlc1RvVXVpZCA9IHJlcXVpcmUoJy4vbGliL2J5dGVzVG9VdWlkJyk7XG5cbmZ1bmN0aW9uIHY0KG9wdGlvbnMsIGJ1Ziwgb2Zmc2V0KSB7XG4gIHZhciBpID0gYnVmICYmIG9mZnNldCB8fCAwO1xuXG4gIGlmICh0eXBlb2Yob3B0aW9ucykgPT0gJ3N0cmluZycpIHtcbiAgICBidWYgPSBvcHRpb25zID09ICdiaW5hcnknID8gbmV3IEFycmF5KDE2KSA6IG51bGw7XG4gICAgb3B0aW9ucyA9IG51bGw7XG4gIH1cbiAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG5cbiAgdmFyIHJuZHMgPSBvcHRpb25zLnJhbmRvbSB8fCAob3B0aW9ucy5ybmcgfHwgcm5nKSgpO1xuXG4gIC8vIFBlciA0LjQsIHNldCBiaXRzIGZvciB2ZXJzaW9uIGFuZCBgY2xvY2tfc2VxX2hpX2FuZF9yZXNlcnZlZGBcbiAgcm5kc1s2XSA9IChybmRzWzZdICYgMHgwZikgfCAweDQwO1xuICBybmRzWzhdID0gKHJuZHNbOF0gJiAweDNmKSB8IDB4ODA7XG5cbiAgLy8gQ29weSBieXRlcyB0byBidWZmZXIsIGlmIHByb3ZpZGVkXG4gIGlmIChidWYpIHtcbiAgICBmb3IgKHZhciBpaSA9IDA7IGlpIDwgMTY7ICsraWkpIHtcbiAgICAgIGJ1ZltpICsgaWldID0gcm5kc1tpaV07XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIGJ1ZiB8fCBieXRlc1RvVXVpZChybmRzKTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSB2NDtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG52YXIgX19yZWFkID0gKHRoaXMgJiYgdGhpcy5fX3JlYWQpIHx8IGZ1bmN0aW9uIChvLCBuKSB7XG4gICAgdmFyIG0gPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgb1tTeW1ib2wuaXRlcmF0b3JdO1xuICAgIGlmICghbSkgcmV0dXJuIG87XG4gICAgdmFyIGkgPSBtLmNhbGwobyksIHIsIGFyID0gW10sIGU7XG4gICAgdHJ5IHtcbiAgICAgICAgd2hpbGUgKChuID09PSB2b2lkIDAgfHwgbi0tID4gMCkgJiYgIShyID0gaS5uZXh0KCkpLmRvbmUpIGFyLnB1c2goci52YWx1ZSk7XG4gICAgfVxuICAgIGNhdGNoIChlcnJvcikgeyBlID0geyBlcnJvcjogZXJyb3IgfTsgfVxuICAgIGZpbmFsbHkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgaWYgKHIgJiYgIXIuZG9uZSAmJiAobSA9IGlbXCJyZXR1cm5cIl0pKSBtLmNhbGwoaSk7XG4gICAgICAgIH1cbiAgICAgICAgZmluYWxseSB7IGlmIChlKSB0aHJvdyBlLmVycm9yOyB9XG4gICAgfVxuICAgIHJldHVybiBhcjtcbn07XG52YXIgX19zcHJlYWQgPSAodGhpcyAmJiB0aGlzLl9fc3ByZWFkKSB8fCBmdW5jdGlvbiAoKSB7XG4gICAgZm9yICh2YXIgYXIgPSBbXSwgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspIGFyID0gYXIuY29uY2F0KF9fcmVhZChhcmd1bWVudHNbaV0pKTtcbiAgICByZXR1cm4gYXI7XG59O1xudmFyIF9fdmFsdWVzID0gKHRoaXMgJiYgdGhpcy5fX3ZhbHVlcykgfHwgZnVuY3Rpb24gKG8pIHtcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl0sIGkgPSAwO1xuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xuICAgIHJldHVybiB7XG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGlmIChvICYmIGkgPj0gby5sZW5ndGgpIG8gPSB2b2lkIDA7XG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XG4gICAgICAgIH1cbiAgICB9O1xufTtcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbnZhciBzaGFkb3dzb2Nrc19jb25maWdfMSA9IHJlcXVpcmUoXCJTaGFkb3dzb2Nrc0NvbmZpZy9zaGFkb3dzb2Nrc19jb25maWdcIik7XG52YXIgZXJyb3JzID0gcmVxdWlyZShcIi4uL21vZGVsL2Vycm9yc1wiKTtcbnZhciBldmVudHMgPSByZXF1aXJlKFwiLi4vbW9kZWwvZXZlbnRzXCIpO1xudmFyIHNldHRpbmdzXzEgPSByZXF1aXJlKFwiLi9zZXR0aW5nc1wiKTtcbi8vIElmIHMgaXMgYSBVUkwgd2hvc2UgZnJhZ21lbnQgY29udGFpbnMgYSBTaGFkb3dzb2NrcyBVUkwgdGhlbiByZXR1cm4gdGhhdCBTaGFkb3dzb2NrcyBVUkwsXG4vLyBvdGhlcndpc2UgcmV0dXJuIHMuXG5mdW5jdGlvbiB1bndyYXBJbnZpdGUocykge1xuICAgIHRyeSB7XG4gICAgICAgIHZhciB1cmwgPSBuZXcgVVJMKHMpO1xuICAgICAgICBpZiAodXJsLmhhc2gpIHtcbiAgICAgICAgICAgIHZhciBkZWNvZGVkRnJhZ21lbnQgPSBkZWNvZGVVUklDb21wb25lbnQodXJsLmhhc2gpO1xuICAgICAgICAgICAgLy8gU2VhcmNoIGluIHRoZSBmcmFnbWVudCBmb3Igc3M6Ly8gZm9yIHR3byByZWFzb25zOlxuICAgICAgICAgICAgLy8gIC0gVVJMLmhhc2ggaW5jbHVkZXMgdGhlIGxlYWRpbmcgIyAod2hhdCkuXG4gICAgICAgICAgICAvLyAgLSBXaGVuIGEgdXNlciBvcGVucyBpbnZpdGUuaHRtbCNFTkNPREVEU1NVUkwgaW4gdGhlaXIgYnJvd3NlciwgdGhlIHdlYnNpdGUgKGN1cnJlbnRseSlcbiAgICAgICAgICAgIC8vICAgIHJlZGlyZWN0cyB0byBpbnZpdGUuaHRtbCMvZW4vaW52aXRlL0VOQ09ERURTU1VSTC4gU2luY2UgY29weWluZyB0aGF0IHJlZGlyZWN0ZWQgVVJMXG4gICAgICAgICAgICAvLyAgICBzZWVtcyBsaWtlIGEgcmVhc29uYWJsZSB0aGluZyB0byBkbywgbGV0J3Mgc3VwcG9ydCB0aG9zZSBVUkxzIHRvby5cbiAgICAgICAgICAgIHZhciBwb3NzaWJsZVNoYWRvd3NvY2tzVXJsID0gZGVjb2RlZEZyYWdtZW50LnN1YnN0cmluZyhkZWNvZGVkRnJhZ21lbnQuaW5kZXhPZignc3M6Ly8nKSk7XG4gICAgICAgICAgICBpZiAobmV3IFVSTChwb3NzaWJsZVNoYWRvd3NvY2tzVXJsKS5wcm90b2NvbCA9PT0gJ3NzOicpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gcG9zc2libGVTaGFkb3dzb2Nrc1VybDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbiAgICBjYXRjaCAoZSkge1xuICAgICAgICAvLyBTb21ldGhpbmcgd2Fzbid0IGEgVVJMLCBvciBpdCBjb3VsZG4ndCBiZSBkZWNvZGVkIC0gbm8gcHJvYmxlbSwgcGVvcGxlIHB1dCBhbGwga2luZHMgb2ZcbiAgICAgICAgLy8gY3JhenkgdGhpbmdzIGluIHRoZSBjbGlwYm9hcmQuXG4gICAgfVxuICAgIHJldHVybiBzO1xufVxuZXhwb3J0cy51bndyYXBJbnZpdGUgPSB1bndyYXBJbnZpdGU7XG52YXIgQXBwID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIEFwcChldmVudFF1ZXVlLCBzZXJ2ZXJSZXBvLCByb290RWwsIGRlYnVnTW9kZSwgdXJsSW50ZXJjZXB0b3IsIGNsaXBib2FyZCwgZXJyb3JSZXBvcnRlciwgc2V0dGluZ3MsIGVudmlyb25tZW50VmFycywgdXBkYXRlciwgcXVpdEFwcGxpY2F0aW9uLCBkb2N1bWVudCkge1xuICAgICAgICBpZiAoZG9jdW1lbnQgPT09IHZvaWQgMCkgeyBkb2N1bWVudCA9IHdpbmRvdy5kb2N1bWVudDsgfVxuICAgICAgICB0aGlzLmV2ZW50UXVldWUgPSBldmVudFF1ZXVlO1xuICAgICAgICB0aGlzLnNlcnZlclJlcG8gPSBzZXJ2ZXJSZXBvO1xuICAgICAgICB0aGlzLnJvb3RFbCA9IHJvb3RFbDtcbiAgICAgICAgdGhpcy5kZWJ1Z01vZGUgPSBkZWJ1Z01vZGU7XG4gICAgICAgIHRoaXMuY2xpcGJvYXJkID0gY2xpcGJvYXJkO1xuICAgICAgICB0aGlzLmVycm9yUmVwb3J0ZXIgPSBlcnJvclJlcG9ydGVyO1xuICAgICAgICB0aGlzLnNldHRpbmdzID0gc2V0dGluZ3M7XG4gICAgICAgIHRoaXMuZW52aXJvbm1lbnRWYXJzID0gZW52aXJvbm1lbnRWYXJzO1xuICAgICAgICB0aGlzLnVwZGF0ZXIgPSB1cGRhdGVyO1xuICAgICAgICB0aGlzLnF1aXRBcHBsaWNhdGlvbiA9IHF1aXRBcHBsaWNhdGlvbjtcbiAgICAgICAgdGhpcy5pZ25vcmVkQWNjZXNzS2V5cyA9IHt9O1xuICAgICAgICB0aGlzLnNlcnZlckxpc3RFbCA9IHJvb3RFbC4kLnNlcnZlcnNWaWV3LiQuc2VydmVyTGlzdDtcbiAgICAgICAgdGhpcy5mZWVkYmFja1ZpZXdFbCA9IHJvb3RFbC4kLmZlZWRiYWNrVmlldztcbiAgICAgICAgdGhpcy5zeW5jU2VydmVyc1RvVUkoKTtcbiAgICAgICAgdGhpcy5zeW5jQ29ubmVjdGl2aXR5U3RhdGVUb1NlcnZlckNhcmRzKCk7XG4gICAgICAgIHJvb3RFbC4kLmFib3V0Vmlldy52ZXJzaW9uID0gZW52aXJvbm1lbnRWYXJzLkFQUF9WRVJTSU9OO1xuICAgICAgICB0aGlzLmxvY2FsaXplID0gdGhpcy5yb290RWwubG9jYWxpemUuYmluZCh0aGlzLnJvb3RFbCk7XG4gICAgICAgIGlmICh1cmxJbnRlcmNlcHRvcikge1xuICAgICAgICAgICAgdGhpcy5yZWdpc3RlclVybEludGVyY2VwdGlvbkxpc3RlbmVyKHVybEludGVyY2VwdG9yKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUud2Fybignbm8gdXJsSW50ZXJjZXB0b3IsIHNzOi8vIHVybHMgd2lsbCBub3QgYmUgaW50ZXJjZXB0ZWQnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLmNsaXBib2FyZC5zZXRMaXN0ZW5lcih0aGlzLmhhbmRsZUNsaXBib2FyZFRleHQuYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMudXBkYXRlci5zZXRMaXN0ZW5lcih0aGlzLnVwZGF0ZURvd25sb2FkZWQuYmluZCh0aGlzKSk7XG4gICAgICAgIC8vIFJlZ2lzdGVyIENvcmRvdmEgbW9iaWxlIGZvcmVncm91bmQgZXZlbnQgdG8gc3luYyBzZXJ2ZXIgY29ubmVjdGl2aXR5LlxuICAgICAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdyZXN1bWUnLCB0aGlzLnN5bmNDb25uZWN0aXZpdHlTdGF0ZVRvU2VydmVyQ2FyZHMuYmluZCh0aGlzKSk7XG4gICAgICAgIC8vIFJlZ2lzdGVyIGhhbmRsZXJzIGZvciBldmVudHMgZmlyZWQgYnkgUG9seW1lciBjb21wb25lbnRzLlxuICAgICAgICB0aGlzLnJvb3RFbC5hZGRFdmVudExpc3RlbmVyKCdQcm9tcHRBZGRTZXJ2ZXJSZXF1ZXN0ZWQnLCB0aGlzLnJlcXVlc3RQcm9tcHRBZGRTZXJ2ZXIuYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMucm9vdEVsLmFkZEV2ZW50TGlzdGVuZXIoJ0FkZFNlcnZlckNvbmZpcm1hdGlvblJlcXVlc3RlZCcsIHRoaXMucmVxdWVzdEFkZFNlcnZlckNvbmZpcm1hdGlvbi5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5yb290RWwuYWRkRXZlbnRMaXN0ZW5lcignQWRkU2VydmVyUmVxdWVzdGVkJywgdGhpcy5yZXF1ZXN0QWRkU2VydmVyLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLnJvb3RFbC5hZGRFdmVudExpc3RlbmVyKCdJZ25vcmVTZXJ2ZXJSZXF1ZXN0ZWQnLCB0aGlzLnJlcXVlc3RJZ25vcmVTZXJ2ZXIuYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMucm9vdEVsLmFkZEV2ZW50TGlzdGVuZXIoJ0Nvbm5lY3RQcmVzc2VkJywgdGhpcy5jb25uZWN0U2VydmVyLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLnJvb3RFbC5hZGRFdmVudExpc3RlbmVyKCdEaXNjb25uZWN0UHJlc3NlZCcsIHRoaXMuZGlzY29ubmVjdFNlcnZlci5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5yb290RWwuYWRkRXZlbnRMaXN0ZW5lcignRm9yZ2V0UHJlc3NlZCcsIHRoaXMuZm9yZ2V0U2VydmVyLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLnJvb3RFbC5hZGRFdmVudExpc3RlbmVyKCdSZW5hbWVSZXF1ZXN0ZWQnLCB0aGlzLnJlbmFtZVNlcnZlci5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5yb290RWwuYWRkRXZlbnRMaXN0ZW5lcignUXVpdFByZXNzZWQnLCB0aGlzLnF1aXRBcHBsaWNhdGlvbi5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5yb290RWwuYWRkRXZlbnRMaXN0ZW5lcignQXV0b0Nvbm5lY3REaWFsb2dEaXNtaXNzZWQnLCB0aGlzLmF1dG9Db25uZWN0RGlhbG9nRGlzbWlzc2VkLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLnJvb3RFbC5hZGRFdmVudExpc3RlbmVyKCdTaG93U2VydmVyUmVuYW1lJywgdGhpcy5yb290RWwuc2hvd1NlcnZlclJlbmFtZS5iaW5kKHRoaXMucm9vdEVsKSk7XG4gICAgICAgIHRoaXMuZmVlZGJhY2tWaWV3RWwuJC5zdWJtaXRCdXR0b24uYWRkRXZlbnRMaXN0ZW5lcigndGFwJywgdGhpcy5zdWJtaXRGZWVkYmFjay5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5yb290RWwuYWRkRXZlbnRMaXN0ZW5lcignUHJpdmFjeVRlcm1zQWNrZWQnLCB0aGlzLmFja1ByaXZhY3lUZXJtcy5iaW5kKHRoaXMpKTtcbiAgICAgICAgLy8gUmVnaXN0ZXIgaGFuZGxlcnMgZm9yIGV2ZW50cyBwdWJsaXNoZWQgdG8gb3VyIGV2ZW50IHF1ZXVlLlxuICAgICAgICB0aGlzLmV2ZW50UXVldWUuc3Vic2NyaWJlKGV2ZW50cy5TZXJ2ZXJBZGRlZCwgdGhpcy5zaG93U2VydmVyQWRkZWQuYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMuZXZlbnRRdWV1ZS5zdWJzY3JpYmUoZXZlbnRzLlNlcnZlckZvcmdvdHRlbiwgdGhpcy5zaG93U2VydmVyRm9yZ290dGVuLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLmV2ZW50UXVldWUuc3Vic2NyaWJlKGV2ZW50cy5TZXJ2ZXJSZW5hbWVkLCB0aGlzLnNob3dTZXJ2ZXJSZW5hbWVkLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLmV2ZW50UXVldWUuc3Vic2NyaWJlKGV2ZW50cy5TZXJ2ZXJGb3JnZXRVbmRvbmUsIHRoaXMuc2hvd1NlcnZlckZvcmdldFVuZG9uZS5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlLnN1YnNjcmliZShldmVudHMuU2VydmVyQ29ubmVjdGVkLCB0aGlzLnNob3dTZXJ2ZXJDb25uZWN0ZWQuYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMuZXZlbnRRdWV1ZS5zdWJzY3JpYmUoZXZlbnRzLlNlcnZlckRpc2Nvbm5lY3RlZCwgdGhpcy5zaG93U2VydmVyRGlzY29ubmVjdGVkLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLmV2ZW50UXVldWUuc3Vic2NyaWJlKGV2ZW50cy5TZXJ2ZXJSZWNvbm5lY3RpbmcsIHRoaXMuc2hvd1NlcnZlclJlY29ubmVjdGluZy5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlLnN0YXJ0UHVibGlzaGluZygpO1xuICAgICAgICBpZiAoIXRoaXMuYXJlUHJpdmFjeVRlcm1zQWNrZWQoKSkge1xuICAgICAgICAgICAgdGhpcy5kaXNwbGF5UHJpdmFjeVZpZXcoKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLmRpc3BsYXlaZXJvU3RhdGVVaSgpO1xuICAgICAgICB0aGlzLnB1bGxDbGlwYm9hcmRUZXh0KCk7XG4gICAgfVxuICAgIEFwcC5wcm90b3R5cGUuc2hvd0xvY2FsaXplZEVycm9yID0gZnVuY3Rpb24gKGUsIHRvYXN0RHVyYXRpb24pIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHRvYXN0RHVyYXRpb24gPT09IHZvaWQgMCkgeyB0b2FzdER1cmF0aW9uID0gMTAwMDA7IH1cbiAgICAgICAgdmFyIG1lc3NhZ2VLZXk7XG4gICAgICAgIHZhciBtZXNzYWdlUGFyYW1zO1xuICAgICAgICB2YXIgYnV0dG9uS2V5O1xuICAgICAgICB2YXIgYnV0dG9uSGFuZGxlcjtcbiAgICAgICAgdmFyIGJ1dHRvbkxpbms7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLlZwblBlcm1pc3Npb25Ob3RHcmFudGVkKSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ291dGxpbmUtcGx1Z2luLWVycm9yLXZwbi1wZXJtaXNzaW9uLW5vdC1ncmFudGVkJztcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLkludmFsaWRTZXJ2ZXJDcmVkZW50aWFscykge1xuICAgICAgICAgICAgbWVzc2FnZUtleSA9ICdvdXRsaW5lLXBsdWdpbi1lcnJvci1pbnZhbGlkLXNlcnZlci1jcmVkZW50aWFscyc7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIGVycm9ycy5SZW1vdGVVZHBGb3J3YXJkaW5nRGlzYWJsZWQpIHtcbiAgICAgICAgICAgIG1lc3NhZ2VLZXkgPSAnb3V0bGluZS1wbHVnaW4tZXJyb3ItdWRwLWZvcndhcmRpbmctbm90LWVuYWJsZWQnO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBlcnJvcnMuU2VydmVyVW5yZWFjaGFibGUpIHtcbiAgICAgICAgICAgIG1lc3NhZ2VLZXkgPSAnb3V0bGluZS1wbHVnaW4tZXJyb3Itc2VydmVyLXVucmVhY2hhYmxlJztcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLkZlZWRiYWNrU3VibWlzc2lvbkVycm9yKSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ2Vycm9yLWZlZWRiYWNrLXN1Ym1pc3Npb24nO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBlcnJvcnMuU2VydmVyVXJsSW52YWxpZCkge1xuICAgICAgICAgICAgbWVzc2FnZUtleSA9ICdlcnJvci1pbnZhbGlkLWFjY2Vzcy1rZXknO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBlcnJvcnMuU2VydmVySW5jb21wYXRpYmxlKSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ2Vycm9yLXNlcnZlci1pbmNvbXBhdGlibGUnO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBlcnJvcnMuT3BlcmF0aW9uVGltZWRPdXQpIHtcbiAgICAgICAgICAgIG1lc3NhZ2VLZXkgPSAnZXJyb3ItdGltZW91dCc7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIGVycm9ycy5TaGFkb3dzb2Nrc1N0YXJ0RmFpbHVyZSAmJiB0aGlzLmlzV2luZG93cygpKSB7XG4gICAgICAgICAgICAvLyBGYWxsIHRocm91Z2ggdG8gYGVycm9yLXVuZXhwZWN0ZWRgIGZvciBvdGhlciBwbGF0Zm9ybXMuXG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ291dGxpbmUtcGx1Z2luLWVycm9yLWFudGl2aXJ1cyc7XG4gICAgICAgICAgICBidXR0b25LZXkgPSAnZml4LXRoaXMnO1xuICAgICAgICAgICAgYnV0dG9uTGluayA9ICdodHRwczovL3MzLmFtYXpvbmF3cy5jb20vb3V0bGluZS12cG4vaW5kZXguaHRtbCMvZW4vc3VwcG9ydC9hbnRpdmlydXNCbG9jayc7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIGVycm9ycy5Db25maWd1cmVTeXN0ZW1Qcm94eUZhaWx1cmUpIHtcbiAgICAgICAgICAgIG1lc3NhZ2VLZXkgPSAnb3V0bGluZS1wbHVnaW4tZXJyb3Itcm91dGluZy10YWJsZXMnO1xuICAgICAgICAgICAgYnV0dG9uS2V5ID0gJ2ZlZWRiYWNrLXBhZ2UtdGl0bGUnO1xuICAgICAgICAgICAgYnV0dG9uSGFuZGxlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAvLyBUT0RPOiBEcm9wLWRvd24gaGFzIG5vIHNlbGVjdGVkIGl0ZW0sIHdoeSBub3Q/XG4gICAgICAgICAgICAgICAgX3RoaXMucm9vdEVsLmNoYW5nZVBhZ2UoJ2ZlZWRiYWNrJyk7XG4gICAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBlcnJvcnMuTm9BZG1pblBlcm1pc3Npb25zKSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ291dGxpbmUtcGx1Z2luLWVycm9yLWFkbWluLXBlcm1pc3Npb25zJztcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLlVuc3VwcG9ydGVkUm91dGluZ1RhYmxlKSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ291dGxpbmUtcGx1Z2luLWVycm9yLXVuc3VwcG9ydGVkLXJvdXRpbmctdGFibGUnO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBlcnJvcnMuU2VydmVyQWxyZWFkeUFkZGVkKSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ2Vycm9yLXNlcnZlci1hbHJlYWR5LWFkZGVkJztcbiAgICAgICAgICAgIG1lc3NhZ2VQYXJhbXMgPSBbJ3NlcnZlck5hbWUnLCBlLnNlcnZlci5uYW1lXTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLlN5c3RlbUNvbmZpZ3VyYXRpb25FeGNlcHRpb24pIHtcbiAgICAgICAgICAgIG1lc3NhZ2VLZXkgPSAnb3V0bGluZS1wbHVnaW4tZXJyb3Itc3lzdGVtLWNvbmZpZ3VyYXRpb24nO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgbWVzc2FnZUtleSA9ICdlcnJvci11bmV4cGVjdGVkJztcbiAgICAgICAgfVxuICAgICAgICB2YXIgbWVzc2FnZSA9IG1lc3NhZ2VQYXJhbXMgPyB0aGlzLmxvY2FsaXplLmFwcGx5KHRoaXMsIF9fc3ByZWFkKFttZXNzYWdlS2V5XSwgbWVzc2FnZVBhcmFtcykpIDogdGhpcy5sb2NhbGl6ZShtZXNzYWdlS2V5KTtcbiAgICAgICAgLy8gRGVmZXIgYnkgNTAwbXMgc28gdGhhdCB0aGlzIHRvYXN0IGlzIHNob3duIGFmdGVyIGFueSB0b2FzdHMgdGhhdCBnZXQgc2hvd24gd2hlbiBhbnlcbiAgICAgICAgLy8gY3VycmVudGx5LWluLWZsaWdodCBkb21haW4gZXZlbnRzIGxhbmQgKGUuZy4gZmFrZSBzZXJ2ZXJzIGFkZGVkKS5cbiAgICAgICAgaWYgKHRoaXMucm9vdEVsICYmIHRoaXMucm9vdEVsLmFzeW5jKSB7XG4gICAgICAgICAgICB0aGlzLnJvb3RFbC5hc3luYyhmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMucm9vdEVsLnNob3dUb2FzdChtZXNzYWdlLCB0b2FzdER1cmF0aW9uLCBidXR0b25LZXkgPyBfdGhpcy5sb2NhbGl6ZShidXR0b25LZXkpIDogdW5kZWZpbmVkLCBidXR0b25IYW5kbGVyLCBidXR0b25MaW5rKTtcbiAgICAgICAgICAgIH0sIDUwMCk7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUucHVsbENsaXBib2FyZFRleHQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHRoaXMuY2xpcGJvYXJkLmdldENvbnRlbnRzKCkudGhlbihmdW5jdGlvbiAodGV4dCkge1xuICAgICAgICAgICAgX3RoaXMuaGFuZGxlQ2xpcGJvYXJkVGV4dCh0ZXh0KTtcbiAgICAgICAgfSwgZnVuY3Rpb24gKGUpIHtcbiAgICAgICAgICAgIGNvbnNvbGUud2FybignY2Fubm90IHJlYWQgY2xpcGJvYXJkLCBzeXN0ZW0gbWF5IGxhY2sgY2xpcGJvYXJkIHN1cHBvcnQnKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnNob3dTZXJ2ZXJDb25uZWN0ZWQgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgY29uc29sZS5kZWJ1ZyhcInNlcnZlciBcIiArIGV2ZW50LnNlcnZlci5pZCArIFwiIGNvbm5lY3RlZFwiKTtcbiAgICAgICAgdmFyIGNhcmQgPSB0aGlzLnNlcnZlckxpc3RFbC5nZXRTZXJ2ZXJDYXJkKGV2ZW50LnNlcnZlci5pZCk7XG4gICAgICAgIGNhcmQuc3RhdGUgPSAnQ09OTkVDVEVEJztcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuc2hvd1NlcnZlckRpc2Nvbm5lY3RlZCA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICBjb25zb2xlLmRlYnVnKFwic2VydmVyIFwiICsgZXZlbnQuc2VydmVyLmlkICsgXCIgZGlzY29ubmVjdGVkXCIpO1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgdGhpcy5zZXJ2ZXJMaXN0RWwuZ2V0U2VydmVyQ2FyZChldmVudC5zZXJ2ZXIuaWQpLnN0YXRlID0gJ0RJU0NPTk5FQ1RFRCc7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgIGNvbnNvbGUud2Fybignc2VydmVyIGNhcmQgbm90IGZvdW5kIGFmdGVyIGRpc2Nvbm5lY3Rpb24gZXZlbnQsIGFzc3VtaW5nIGZvcmdvdHRlbicpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnNob3dTZXJ2ZXJSZWNvbm5lY3RpbmcgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgY29uc29sZS5kZWJ1ZyhcInNlcnZlciBcIiArIGV2ZW50LnNlcnZlci5pZCArIFwiIHJlY29ubmVjdGluZ1wiKTtcbiAgICAgICAgdmFyIGNhcmQgPSB0aGlzLnNlcnZlckxpc3RFbC5nZXRTZXJ2ZXJDYXJkKGV2ZW50LnNlcnZlci5pZCk7XG4gICAgICAgIGNhcmQuc3RhdGUgPSAnUkVDT05ORUNUSU5HJztcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuZGlzcGxheVplcm9TdGF0ZVVpID0gZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAodGhpcy5yb290RWwuJC5zZXJ2ZXJzVmlldy5zaG91bGRTaG93WmVyb1N0YXRlKSB7XG4gICAgICAgICAgICB0aGlzLnJvb3RFbC4kLmFkZFNlcnZlclZpZXcub3BlbkFkZFNlcnZlclNoZWV0KCk7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuYXJlUHJpdmFjeVRlcm1zQWNrZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5zZXR0aW5ncy5nZXQoc2V0dGluZ3NfMS5TZXR0aW5nc0tleS5QUklWQUNZX0FDSykgPT09ICd0cnVlJztcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZSkge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcihcImNvdWxkIG5vdCByZWFkIHByaXZhY3kgYWNrbm93bGVkZ2VtZW50IHNldHRpbmcsIGFzc3VtaW5nIG5vdCBhY2tub3dsZWRnZWRcIik7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5kaXNwbGF5UHJpdmFjeVZpZXcgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRoaXMucm9vdEVsLiQuc2VydmVyc1ZpZXcuaGlkZGVuID0gdHJ1ZTtcbiAgICAgICAgdGhpcy5yb290RWwuJC5wcml2YWN5Vmlldy5oaWRkZW4gPSBmYWxzZTtcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuYWNrUHJpdmFjeVRlcm1zID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB0aGlzLnJvb3RFbC4kLnNlcnZlcnNWaWV3LmhpZGRlbiA9IGZhbHNlO1xuICAgICAgICB0aGlzLnJvb3RFbC4kLnByaXZhY3lWaWV3LmhpZGRlbiA9IHRydWU7XG4gICAgICAgIHRoaXMuc2V0dGluZ3Muc2V0KHNldHRpbmdzXzEuU2V0dGluZ3NLZXkuUFJJVkFDWV9BQ0ssICd0cnVlJyk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLmhhbmRsZUNsaXBib2FyZFRleHQgPSBmdW5jdGlvbiAodGV4dCkge1xuICAgICAgICAvLyBTaG9ydGVuLCBzYW5pdGlzZS5cbiAgICAgICAgLy8gTm90ZSB0aGF0IHdlIGFsd2F5cyBjaGVjayB0aGUgdGV4dCwgZXZlbiBpZiB0aGUgY29udGVudHMgYXJlIHNhbWUgYXMgbGFzdCB0aW1lLCBiZWNhdXNlIHdlXG4gICAgICAgIC8vIGtlZXAgYW4gaW4tbWVtb3J5IGNhY2hlIG9mIHVzZXItaWdub3JlZCBhY2Nlc3Mga2V5cy5cbiAgICAgICAgdGV4dCA9IHRleHQuc3Vic3RyaW5nKDAsIDEwMDApLnRyaW0oKTtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHRoaXMuY29uZmlybUFkZFNlcnZlcih0ZXh0LCB0cnVlKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgICAgICAvLyBEb24ndCBhbGVydCB0aGUgdXNlcjsgaGlnaCBmYWxzZSBwb3NpdGl2ZSByYXRlLlxuICAgICAgICB9XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnVwZGF0ZURvd25sb2FkZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRoaXMucm9vdEVsLnNob3dUb2FzdCh0aGlzLmxvY2FsaXplKCd1cGRhdGUtZG93bmxvYWRlZCcpLCA2MDAwMCk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnJlcXVlc3RQcm9tcHRBZGRTZXJ2ZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRoaXMucm9vdEVsLnByb21wdEFkZFNlcnZlcigpO1xuICAgIH07XG4gICAgLy8gQ2FjaGVzIGFuIGlnbm9yZWQgc2VydmVyIGFjY2VzcyBrZXkgc28gd2UgZG9uJ3QgcHJvbXB0IHRoZSB1c2VyIHRvIGFkZCBpdCBhZ2Fpbi5cbiAgICBBcHAucHJvdG90eXBlLnJlcXVlc3RJZ25vcmVTZXJ2ZXIgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgdmFyIGFjY2Vzc0tleSA9IGV2ZW50LmRldGFpbC5hY2Nlc3NLZXk7XG4gICAgICAgIHRoaXMuaWdub3JlZEFjY2Vzc0tleXNbYWNjZXNzS2V5XSA9IHRydWU7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnJlcXVlc3RBZGRTZXJ2ZXIgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHRoaXMuc2VydmVyUmVwby5hZGQoZXZlbnQuZGV0YWlsLnNlcnZlckNvbmZpZyk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGVycikge1xuICAgICAgICAgICAgdGhpcy5jaGFuZ2VUb0RlZmF1bHRQYWdlKCk7XG4gICAgICAgICAgICB0aGlzLnNob3dMb2NhbGl6ZWRFcnJvcihlcnIpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnJlcXVlc3RBZGRTZXJ2ZXJDb25maXJtYXRpb24gPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgdmFyIGFjY2Vzc0tleSA9IGV2ZW50LmRldGFpbC5hY2Nlc3NLZXk7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ0dvdCBhZGQgc2VydmVyIGNvbmZpcm1hdGlvbiByZXF1ZXN0IGZyb20gVUknKTtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHRoaXMuY29uZmlybUFkZFNlcnZlcihhY2Nlc3NLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlcnIpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0ZhaWxlZCB0byBjb25maXJtIGFkZCBzZXZlci4nLCBlcnIpO1xuICAgICAgICAgICAgdmFyIGFkZFNlcnZlclZpZXcgPSB0aGlzLnJvb3RFbC4kLmFkZFNlcnZlclZpZXc7XG4gICAgICAgICAgICBhZGRTZXJ2ZXJWaWV3LiQuYWNjZXNzS2V5SW5wdXQuaW52YWxpZCA9IHRydWU7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuY29uZmlybUFkZFNlcnZlciA9IGZ1bmN0aW9uIChhY2Nlc3NLZXksIGZyb21DbGlwYm9hcmQpIHtcbiAgICAgICAgaWYgKGZyb21DbGlwYm9hcmQgPT09IHZvaWQgMCkgeyBmcm9tQ2xpcGJvYXJkID0gZmFsc2U7IH1cbiAgICAgICAgdmFyIGFkZFNlcnZlclZpZXcgPSB0aGlzLnJvb3RFbC4kLmFkZFNlcnZlclZpZXc7XG4gICAgICAgIGFjY2Vzc0tleSA9IHVud3JhcEludml0ZShhY2Nlc3NLZXkpO1xuICAgICAgICBpZiAoZnJvbUNsaXBib2FyZCAmJiBhY2Nlc3NLZXkgaW4gdGhpcy5pZ25vcmVkQWNjZXNzS2V5cykge1xuICAgICAgICAgICAgcmV0dXJuIGNvbnNvbGUuZGVidWcoJ0lnbm9yaW5nIGFjY2VzcyBrZXknKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChmcm9tQ2xpcGJvYXJkICYmIGFkZFNlcnZlclZpZXcuaXNBZGRpbmdTZXJ2ZXIoKSkge1xuICAgICAgICAgICAgcmV0dXJuIGNvbnNvbGUuZGVidWcoJ0FscmVhZHkgYWRkaW5nIGEgc2VydmVyJyk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gRXhwZWN0IFNIQURPV1NPQ0tTX1VSSS5wYXJzZSB0byB0aHJvdyBvbiBpbnZhbGlkIGFjY2VzcyBrZXk7IHByb3BhZ2F0ZSBhbnkgZXhjZXB0aW9uLlxuICAgICAgICB2YXIgc2hhZG93c29ja3NDb25maWcgPSBudWxsO1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgc2hhZG93c29ja3NDb25maWcgPSBzaGFkb3dzb2Nrc19jb25maWdfMS5TSEFET1dTT0NLU19VUkkucGFyc2UoYWNjZXNzS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgIHZhciBtZXNzYWdlID0gISFlcnJvci5tZXNzYWdlID8gZXJyb3IubWVzc2FnZSA6ICdGYWlsZWQgdG8gcGFyc2UgYWNjZXNzIGtleSc7XG4gICAgICAgICAgICB0aHJvdyBuZXcgZXJyb3JzLlNlcnZlclVybEludmFsaWQobWVzc2FnZSk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHNoYWRvd3NvY2tzQ29uZmlnLmhvc3QuaXNJUHY2KSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgZXJyb3JzLlNlcnZlckluY29tcGF0aWJsZSgnT25seSBJUHY0IGFkZHJlc3NlcyBhcmUgY3VycmVudGx5IHN1cHBvcnRlZCcpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBuYW1lID0gc2hhZG93c29ja3NDb25maWcuZXh0cmEub3V0bGluZSA/XG4gICAgICAgICAgICB0aGlzLmxvY2FsaXplKCdzZXJ2ZXItZGVmYXVsdC1uYW1lLW91dGxpbmUnKSA6XG4gICAgICAgICAgICBzaGFkb3dzb2Nrc0NvbmZpZy50YWcuZGF0YSA/IHNoYWRvd3NvY2tzQ29uZmlnLnRhZy5kYXRhIDpcbiAgICAgICAgICAgICAgICB0aGlzLmxvY2FsaXplKCdzZXJ2ZXItZGVmYXVsdC1uYW1lJyk7XG4gICAgICAgIHZhciBzZXJ2ZXJDb25maWcgPSB7XG4gICAgICAgICAgICBob3N0OiBzaGFkb3dzb2Nrc0NvbmZpZy5ob3N0LmRhdGEsXG4gICAgICAgICAgICBwb3J0OiBzaGFkb3dzb2Nrc0NvbmZpZy5wb3J0LmRhdGEsXG4gICAgICAgICAgICBtZXRob2Q6IHNoYWRvd3NvY2tzQ29uZmlnLm1ldGhvZC5kYXRhLFxuICAgICAgICAgICAgcGFzc3dvcmQ6IHNoYWRvd3NvY2tzQ29uZmlnLnBhc3N3b3JkLmRhdGEsXG4gICAgICAgICAgICBuYW1lOiBuYW1lLFxuICAgICAgICB9O1xuICAgICAgICBpZiAoIXRoaXMuc2VydmVyUmVwby5jb250YWluc1NlcnZlcihzZXJ2ZXJDb25maWcpKSB7XG4gICAgICAgICAgICAvLyBPbmx5IHByb21wdCB0aGUgdXNlciB0byBhZGQgbmV3IHNlcnZlcnMuXG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGFkZFNlcnZlclZpZXcub3BlbkFkZFNlcnZlckNvbmZpcm1hdGlvblNoZWV0KGFjY2Vzc0tleSwgc2VydmVyQ29uZmlnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhdGNoIChlcnIpIHtcbiAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdGYWlsZWQgdG8gb3BlbiBhZGQgc2V2ZXIgY29uZmlybWF0aW9uIHNoZWV0OicsIGVyci5tZXNzYWdlKTtcbiAgICAgICAgICAgICAgICBpZiAoIWZyb21DbGlwYm9hcmQpXG4gICAgICAgICAgICAgICAgICAgIHRoaXMuc2hvd0xvY2FsaXplZEVycm9yKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoIWZyb21DbGlwYm9hcmQpIHtcbiAgICAgICAgICAgIC8vIERpc3BsYXkgZXJyb3IgbWVzc2FnZSBpZiB0aGlzIGlzIG5vdCBhIGNsaXBib2FyZCBhZGQuXG4gICAgICAgICAgICBhZGRTZXJ2ZXJWaWV3LmNsb3NlKCk7XG4gICAgICAgICAgICB0aGlzLnNob3dMb2NhbGl6ZWRFcnJvcihuZXcgZXJyb3JzLlNlcnZlckFscmVhZHlBZGRlZCh0aGlzLnNlcnZlclJlcG8uY3JlYXRlU2VydmVyKCcnLCBzZXJ2ZXJDb25maWcsIHRoaXMuZXZlbnRRdWV1ZSkpKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5mb3JnZXRTZXJ2ZXIgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgdmFyIHNlcnZlcklkID0gZXZlbnQuZGV0YWlsLnNlcnZlcklkO1xuICAgICAgICB2YXIgc2VydmVyID0gdGhpcy5zZXJ2ZXJSZXBvLmdldEJ5SWQoc2VydmVySWQpO1xuICAgICAgICBpZiAoIXNlcnZlcikge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIk5vIHNlcnZlciB3aXRoIGlkIFwiICsgc2VydmVySWQpO1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuc2hvd0xvY2FsaXplZEVycm9yKCk7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIG9uY2VOb3RSdW5uaW5nID0gc2VydmVyLmNoZWNrUnVubmluZygpLnRoZW4oZnVuY3Rpb24gKGlzUnVubmluZykge1xuICAgICAgICAgICAgcmV0dXJuIGlzUnVubmluZyA/IF90aGlzLmRpc2Nvbm5lY3RTZXJ2ZXIoZXZlbnQpIDogUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgIH0pO1xuICAgICAgICBvbmNlTm90UnVubmluZy50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIF90aGlzLnNlcnZlclJlcG8uZm9yZ2V0KHNlcnZlcklkKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnJlbmFtZVNlcnZlciA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICB2YXIgc2VydmVySWQgPSBldmVudC5kZXRhaWwuc2VydmVySWQ7XG4gICAgICAgIHZhciBuZXdOYW1lID0gZXZlbnQuZGV0YWlsLm5ld05hbWU7XG4gICAgICAgIHRoaXMuc2VydmVyUmVwby5yZW5hbWUoc2VydmVySWQsIG5ld05hbWUpO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5jb25uZWN0U2VydmVyID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHZhciBzZXJ2ZXJJZCA9IGV2ZW50LmRldGFpbC5zZXJ2ZXJJZDtcbiAgICAgICAgaWYgKCFzZXJ2ZXJJZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiY29ubmVjdFNlcnZlciBldmVudCBoYWQgbm8gc2VydmVyIElEXCIpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBzZXJ2ZXIgPSB0aGlzLmdldFNlcnZlckJ5U2VydmVySWQoc2VydmVySWQpO1xuICAgICAgICB2YXIgY2FyZCA9IHRoaXMuZ2V0Q2FyZEJ5U2VydmVySWQoc2VydmVySWQpO1xuICAgICAgICBjb25zb2xlLmxvZyhcImNvbm5lY3RpbmcgdG8gc2VydmVyIFwiICsgc2VydmVySWQpO1xuICAgICAgICBjYXJkLnN0YXRlID0gJ0NPTk5FQ1RJTkcnO1xuICAgICAgICBzZXJ2ZXIuY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgY2FyZC5zdGF0ZSA9ICdDT05ORUNURUQnO1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJjb25uZWN0ZWQgdG8gc2VydmVyIFwiICsgc2VydmVySWQpO1xuICAgICAgICAgICAgX3RoaXMucm9vdEVsLnNob3dUb2FzdChfdGhpcy5sb2NhbGl6ZSgnc2VydmVyLWNvbm5lY3RlZCcsICdzZXJ2ZXJOYW1lJywgc2VydmVyLm5hbWUpKTtcbiAgICAgICAgICAgIF90aGlzLm1heWJlU2hvd0F1dG9Db25uZWN0RGlhbG9nKCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uIChlKSB7XG4gICAgICAgICAgICBjYXJkLnN0YXRlID0gJ0RJU0NPTk5FQ1RFRCc7XG4gICAgICAgICAgICBfdGhpcy5zaG93TG9jYWxpemVkRXJyb3IoZSk7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKFwiY291bGQgbm90IGNvbm5lY3QgdG8gc2VydmVyIFwiICsgc2VydmVySWQgKyBcIjogXCIgKyBlLm5hbWUpO1xuICAgICAgICAgICAgaWYgKCEoZSBpbnN0YW5jZW9mIGVycm9ycy5SZWd1bGFyTmF0aXZlRXJyb3IpKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuZXJyb3JSZXBvcnRlci5yZXBvcnQoXCJjb25uZWN0aW9uIGZhaWx1cmU6IFwiICsgZS5uYW1lLCAnY29ubmVjdGlvbi1mYWlsdXJlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5tYXliZVNob3dBdXRvQ29ubmVjdERpYWxvZyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIGRpc21pc3NlZCA9IGZhbHNlO1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgZGlzbWlzc2VkID0gdGhpcy5zZXR0aW5ncy5nZXQoc2V0dGluZ3NfMS5TZXR0aW5nc0tleS5BVVRPX0NPTk5FQ1RfRElBTE9HX0RJU01JU1NFRCkgPT09ICd0cnVlJztcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZSkge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIkZhaWxlZCB0byByZWFkIGF1dG8tY29ubmVjdCBkaWFsb2cgc3RhdHVzLCBhc3N1bWluZyBub3QgZGlzbWlzc2VkOiBcIiArIGUpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghZGlzbWlzc2VkKSB7XG4gICAgICAgICAgICB0aGlzLnJvb3RFbC4kLnNlcnZlcnNWaWV3LiQuYXV0b0Nvbm5lY3REaWFsb2cuc2hvdygpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLmF1dG9Db25uZWN0RGlhbG9nRGlzbWlzc2VkID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB0aGlzLnNldHRpbmdzLnNldChzZXR0aW5nc18xLlNldHRpbmdzS2V5LkFVVE9fQ09OTkVDVF9ESUFMT0dfRElTTUlTU0VELCAndHJ1ZScpO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5kaXNjb25uZWN0U2VydmVyID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHZhciBzZXJ2ZXJJZCA9IGV2ZW50LmRldGFpbC5zZXJ2ZXJJZDtcbiAgICAgICAgaWYgKCFzZXJ2ZXJJZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiZGlzY29ubmVjdFNlcnZlciBldmVudCBoYWQgbm8gc2VydmVyIElEXCIpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBzZXJ2ZXIgPSB0aGlzLmdldFNlcnZlckJ5U2VydmVySWQoc2VydmVySWQpO1xuICAgICAgICB2YXIgY2FyZCA9IHRoaXMuZ2V0Q2FyZEJ5U2VydmVySWQoc2VydmVySWQpO1xuICAgICAgICBjb25zb2xlLmxvZyhcImRpc2Nvbm5lY3RpbmcgZnJvbSBzZXJ2ZXIgXCIgKyBzZXJ2ZXJJZCk7XG4gICAgICAgIGNhcmQuc3RhdGUgPSAnRElTQ09OTkVDVElORyc7XG4gICAgICAgIHNlcnZlci5kaXNjb25uZWN0KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBjYXJkLnN0YXRlID0gJ0RJU0NPTk5FQ1RFRCc7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcImRpc2Nvbm5lY3RlZCBmcm9tIHNlcnZlciBcIiArIHNlcnZlcklkKTtcbiAgICAgICAgICAgIF90aGlzLnJvb3RFbC5zaG93VG9hc3QoX3RoaXMubG9jYWxpemUoJ3NlcnZlci1kaXNjb25uZWN0ZWQnLCAnc2VydmVyTmFtZScsIHNlcnZlci5uYW1lKSk7XG4gICAgICAgIH0sIGZ1bmN0aW9uIChlKSB7XG4gICAgICAgICAgICBjYXJkLnN0YXRlID0gJ0NPTk5FQ1RFRCc7XG4gICAgICAgICAgICBfdGhpcy5zaG93TG9jYWxpemVkRXJyb3IoZSk7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oXCJjb3VsZCBub3QgZGlzY29ubmVjdCBmcm9tIHNlcnZlciBcIiArIHNlcnZlcklkICsgXCI6IFwiICsgZS5uYW1lKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnN1Ym1pdEZlZWRiYWNrID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHZhciBmb3JtRGF0YSA9IHRoaXMuZmVlZGJhY2tWaWV3RWwuZ2V0VmFsaWRhdGVkRm9ybURhdGEoKTtcbiAgICAgICAgaWYgKCFmb3JtRGF0YSkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIHZhciBmZWVkYmFjayA9IGZvcm1EYXRhLmZlZWRiYWNrLCBjYXRlZ29yeSA9IGZvcm1EYXRhLmNhdGVnb3J5LCBlbWFpbCA9IGZvcm1EYXRhLmVtYWlsO1xuICAgICAgICB0aGlzLnJvb3RFbC4kLmZlZWRiYWNrVmlldy5zdWJtaXR0aW5nID0gdHJ1ZTtcbiAgICAgICAgdGhpcy5lcnJvclJlcG9ydGVyLnJlcG9ydChmZWVkYmFjaywgY2F0ZWdvcnksIGVtYWlsKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgX3RoaXMucm9vdEVsLiQuZmVlZGJhY2tWaWV3LnN1Ym1pdHRpbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIF90aGlzLnJvb3RFbC4kLmZlZWRiYWNrVmlldy5yZXNldEZvcm0oKTtcbiAgICAgICAgICAgIF90aGlzLmNoYW5nZVRvRGVmYXVsdFBhZ2UoKTtcbiAgICAgICAgICAgIF90aGlzLnJvb3RFbC5zaG93VG9hc3QoX3RoaXMucm9vdEVsLmxvY2FsaXplKCdmZWVkYmFjay10aGFua3MnKSk7XG4gICAgICAgIH0sIGZ1bmN0aW9uIChlcnIpIHtcbiAgICAgICAgICAgIF90aGlzLnJvb3RFbC4kLmZlZWRiYWNrVmlldy5zdWJtaXR0aW5nID0gZmFsc2U7XG4gICAgICAgICAgICBfdGhpcy5zaG93TG9jYWxpemVkRXJyb3IobmV3IGVycm9ycy5GZWVkYmFja1N1Ym1pc3Npb25FcnJvcigpKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvLyBFdmVudFF1ZXVlIGV2ZW50IGhhbmRsZXJzOlxuICAgIEFwcC5wcm90b3R5cGUuc2hvd1NlcnZlckFkZGVkID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIHZhciBzZXJ2ZXIgPSBldmVudC5zZXJ2ZXI7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ1NlcnZlciBhZGRlZCcpO1xuICAgICAgICB0aGlzLnN5bmNTZXJ2ZXJzVG9VSSgpO1xuICAgICAgICB0aGlzLnN5bmNTZXJ2ZXJDb25uZWN0aXZpdHlTdGF0ZShzZXJ2ZXIpO1xuICAgICAgICB0aGlzLmNoYW5nZVRvRGVmYXVsdFBhZ2UoKTtcbiAgICAgICAgdGhpcy5yb290RWwuc2hvd1RvYXN0KHRoaXMubG9jYWxpemUoJ3NlcnZlci1hZGRlZCcsICdzZXJ2ZXJOYW1lJywgc2VydmVyLm5hbWUpKTtcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuc2hvd1NlcnZlckZvcmdvdHRlbiA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICB2YXIgc2VydmVyID0gZXZlbnQuc2VydmVyO1xuICAgICAgICBjb25zb2xlLmRlYnVnKCdTZXJ2ZXIgZm9yZ290dGVuJyk7XG4gICAgICAgIHRoaXMuc3luY1NlcnZlcnNUb1VJKCk7XG4gICAgICAgIHRoaXMucm9vdEVsLnNob3dUb2FzdCh0aGlzLmxvY2FsaXplKCdzZXJ2ZXItZm9yZ290dGVuJywgJ3NlcnZlck5hbWUnLCBzZXJ2ZXIubmFtZSksIDEwMDAwLCB0aGlzLmxvY2FsaXplKCd1bmRvLWJ1dHRvbi1sYWJlbCcpLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBfdGhpcy5zZXJ2ZXJSZXBvLnVuZG9Gb3JnZXQoc2VydmVyLmlkKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnNob3dTZXJ2ZXJGb3JnZXRVbmRvbmUgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgdGhpcy5zeW5jU2VydmVyc1RvVUkoKTtcbiAgICAgICAgdmFyIHNlcnZlciA9IGV2ZW50LnNlcnZlcjtcbiAgICAgICAgdGhpcy5yb290RWwuc2hvd1RvYXN0KHRoaXMubG9jYWxpemUoJ3NlcnZlci1mb3Jnb3R0ZW4tdW5kbycsICdzZXJ2ZXJOYW1lJywgc2VydmVyLm5hbWUpKTtcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuc2hvd1NlcnZlclJlbmFtZWQgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgdmFyIHNlcnZlciA9IGV2ZW50LnNlcnZlcjtcbiAgICAgICAgY29uc29sZS5kZWJ1ZygnU2VydmVyIHJlbmFtZWQnKTtcbiAgICAgICAgdGhpcy5zZXJ2ZXJMaXN0RWwuZ2V0U2VydmVyQ2FyZChzZXJ2ZXIuaWQpLnNlcnZlck5hbWUgPSBzZXJ2ZXIubmFtZTtcbiAgICAgICAgdGhpcy5yb290RWwuc2hvd1RvYXN0KHRoaXMubG9jYWxpemUoJ3NlcnZlci1yZW5hbWUtY29tcGxldGUnKSk7XG4gICAgfTtcbiAgICAvLyBIZWxwZXJzOlxuICAgIEFwcC5wcm90b3R5cGUuc3luY1NlcnZlcnNUb1VJID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB0aGlzLnJvb3RFbC5zZXJ2ZXJzID0gdGhpcy5zZXJ2ZXJSZXBvLmdldEFsbCgpO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5zeW5jQ29ubmVjdGl2aXR5U3RhdGVUb1NlcnZlckNhcmRzID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgZV8xLCBfYTtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGZvciAodmFyIF9iID0gX192YWx1ZXModGhpcy5zZXJ2ZXJSZXBvLmdldEFsbCgpKSwgX2MgPSBfYi5uZXh0KCk7ICFfYy5kb25lOyBfYyA9IF9iLm5leHQoKSkge1xuICAgICAgICAgICAgICAgIHZhciBzZXJ2ZXIgPSBfYy52YWx1ZTtcbiAgICAgICAgICAgICAgICB0aGlzLnN5bmNTZXJ2ZXJDb25uZWN0aXZpdHlTdGF0ZShzZXJ2ZXIpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlXzFfMSkgeyBlXzEgPSB7IGVycm9yOiBlXzFfMSB9OyB9XG4gICAgICAgIGZpbmFsbHkge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBpZiAoX2MgJiYgIV9jLmRvbmUgJiYgKF9hID0gX2IucmV0dXJuKSkgX2EuY2FsbChfYik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBmaW5hbGx5IHsgaWYgKGVfMSkgdGhyb3cgZV8xLmVycm9yOyB9XG4gICAgICAgIH1cbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuc3luY1NlcnZlckNvbm5lY3Rpdml0eVN0YXRlID0gZnVuY3Rpb24gKHNlcnZlcikge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBzZXJ2ZXIuY2hlY2tSdW5uaW5nKClcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChpc1J1bm5pbmcpIHtcbiAgICAgICAgICAgIHZhciBjYXJkID0gX3RoaXMuc2VydmVyTGlzdEVsLmdldFNlcnZlckNhcmQoc2VydmVyLmlkKTtcbiAgICAgICAgICAgIGlmICghaXNSdW5uaW5nKSB7XG4gICAgICAgICAgICAgICAgY2FyZC5zdGF0ZSA9ICdESVNDT05ORUNURUQnO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHNlcnZlci5jaGVja1JlYWNoYWJsZSgpLnRoZW4oZnVuY3Rpb24gKGlzUmVhY2hhYmxlKSB7XG4gICAgICAgICAgICAgICAgaWYgKGlzUmVhY2hhYmxlKSB7XG4gICAgICAgICAgICAgICAgICAgIGNhcmQuc3RhdGUgPSAnQ09OTkVDVEVEJztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiU2VydmVyIFwiICsgc2VydmVyLmlkICsgXCIgcmVjb25uZWN0aW5nXCIpO1xuICAgICAgICAgICAgICAgICAgICBjYXJkLnN0YXRlID0gJ1JFQ09OTkVDVElORyc7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pXG4gICAgICAgICAgICAuY2F0Y2goZnVuY3Rpb24gKGUpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0ZhaWxlZCB0byBzeW5jIHNlcnZlciBjb25uZWN0aXZpdHkgc3RhdGUnLCBlKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnJlZ2lzdGVyVXJsSW50ZXJjZXB0aW9uTGlzdGVuZXIgPSBmdW5jdGlvbiAodXJsSW50ZXJjZXB0b3IpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgdXJsSW50ZXJjZXB0b3IucmVnaXN0ZXJMaXN0ZW5lcihmdW5jdGlvbiAodXJsKSB7XG4gICAgICAgICAgICBpZiAoIXVybCB8fCAhdW53cmFwSW52aXRlKHVybCkuc3RhcnRzV2l0aCgnc3M6Ly8nKSkge1xuICAgICAgICAgICAgICAgIC8vIFRoaXMgY2hlY2sgaXMgbmVjZXNzYXJ5IHRvIGlnbm9yZSBlbXB0eSBhbmQgbWFsZm9ybWVkIGluc3RhbGwtcmVmZXJyZXIgVVJMcyBpbiBBbmRyb2lkXG4gICAgICAgICAgICAgICAgLy8gd2hpbGUgYWxsb3dpbmcgc3M6Ly8gYW5kIGludml0ZSBVUkxzLlxuICAgICAgICAgICAgICAgIC8vIFRPRE86IFN0b3AgcmVjZWl2aW5nIGluc3RhbGwgcmVmZXJyZXIgaW50ZW50cyBzbyB3ZSBjYW4gcmVtb3ZlIHRoaXMuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGNvbnNvbGUuZGVidWcoXCJJZ25vcmluZyBpbnRlcmNlcHRlZCBub24tc2hhZG93c29ja3MgdXJsXCIpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBfdGhpcy5jb25maXJtQWRkU2VydmVyKHVybCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuc2hvd0xvY2FsaXplZEVycm9ySW5EZWZhdWx0UGFnZShlcnIpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuY2hhbmdlVG9EZWZhdWx0UGFnZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhpcy5yb290RWwuY2hhbmdlUGFnZSh0aGlzLnJvb3RFbC5ERUZBVUxUX1BBR0UpO1xuICAgIH07XG4gICAgLy8gUmV0dXJucyB0aGUgc2VydmVyIGhhdmluZyBzZXJ2ZXJJZCwgdGhyb3dzIGlmIHRoZSBzZXJ2ZXIgY2Fubm90IGJlIGZvdW5kLlxuICAgIEFwcC5wcm90b3R5cGUuZ2V0U2VydmVyQnlTZXJ2ZXJJZCA9IGZ1bmN0aW9uIChzZXJ2ZXJJZCkge1xuICAgICAgICB2YXIgc2VydmVyID0gdGhpcy5zZXJ2ZXJSZXBvLmdldEJ5SWQoc2VydmVySWQpO1xuICAgICAgICBpZiAoIXNlcnZlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiY291bGQgbm90IGZpbmQgc2VydmVyIHdpdGggSUQgXCIgKyBzZXJ2ZXJJZCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHNlcnZlcjtcbiAgICB9O1xuICAgIC8vIFJldHVybnMgdGhlIGNhcmQgYXNzb2NpYXRlZCB3aXRoIHNlcnZlcklkLCB0aHJvd3MgaWYgbm8gc3VjaCBjYXJkIGV4aXN0cy5cbiAgICAvLyBTZWUgc2VydmVyLWxpc3QuaHRtbC5cbiAgICBBcHAucHJvdG90eXBlLmdldENhcmRCeVNlcnZlcklkID0gZnVuY3Rpb24gKHNlcnZlcklkKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnNlcnZlckxpc3RFbC5nZXRTZXJ2ZXJDYXJkKHNlcnZlcklkKTtcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuc2hvd0xvY2FsaXplZEVycm9ySW5EZWZhdWx0UGFnZSA9IGZ1bmN0aW9uIChlcnIpIHtcbiAgICAgICAgdGhpcy5jaGFuZ2VUb0RlZmF1bHRQYWdlKCk7XG4gICAgICAgIHRoaXMuc2hvd0xvY2FsaXplZEVycm9yKGVycik7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLmlzV2luZG93cyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuICEoJ2NvcmRvdmEnIGluIHdpbmRvdyk7XG4gICAgfTtcbiAgICByZXR1cm4gQXBwO1xufSgpKTtcbmV4cG9ydHMuQXBwID0gQXBwO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgMjAxOCBUaGUgT3V0bGluZSBBdXRob3JzXG4vL1xuLy8gTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbi8vIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuLy9cbi8vICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4vL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuLy8gZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4vLyBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbi8vIEdlbmVyaWMgY2xpcGJvYXJkLiBJbXBsZW1lbnRhdGlvbnMgc2hvdWxkIG9ubHkgaGF2ZSB0byBpbXBsZW1lbnQgZ2V0Q29udGVudHMoKS5cbnZhciBBYnN0cmFjdENsaXBib2FyZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBBYnN0cmFjdENsaXBib2FyZCgpIHtcbiAgICAgICAgdGhpcy5saXN0ZW5lciA9IG51bGw7XG4gICAgfVxuICAgIEFic3RyYWN0Q2xpcGJvYXJkLnByb3RvdHlwZS5nZXRDb250ZW50cyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBFcnJvcigndW5pbXBsZW1lbnRlZCBza2VsZXRvbiBtZXRob2QnKSk7XG4gICAgfTtcbiAgICBBYnN0cmFjdENsaXBib2FyZC5wcm90b3R5cGUuc2V0TGlzdGVuZXIgPSBmdW5jdGlvbiAobGlzdGVuZXIpIHtcbiAgICAgICAgdGhpcy5saXN0ZW5lciA9IGxpc3RlbmVyO1xuICAgIH07XG4gICAgQWJzdHJhY3RDbGlwYm9hcmQucHJvdG90eXBlLmVtaXRFdmVudCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKHRoaXMubGlzdGVuZXIpIHtcbiAgICAgICAgICAgIHRoaXMuZ2V0Q29udGVudHMoKS50aGVuKHRoaXMubGlzdGVuZXIpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICByZXR1cm4gQWJzdHJhY3RDbGlwYm9hcmQ7XG59KCkpO1xuZXhwb3J0cy5BYnN0cmFjdENsaXBib2FyZCA9IEFic3RyYWN0Q2xpcGJvYXJkO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgMjAxOCBUaGUgT3V0bGluZSBBdXRob3JzXG4vL1xuLy8gTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbi8vIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuLy9cbi8vICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4vL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuLy8gZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4vLyBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbnZhciBfX2V4dGVuZHMgPSAodGhpcyAmJiB0aGlzLl9fZXh0ZW5kcykgfHwgKGZ1bmN0aW9uICgpIHtcbiAgICB2YXIgZXh0ZW5kU3RhdGljcyA9IGZ1bmN0aW9uIChkLCBiKSB7XG4gICAgICAgIGV4dGVuZFN0YXRpY3MgPSBPYmplY3Quc2V0UHJvdG90eXBlT2YgfHxcbiAgICAgICAgICAgICh7IF9fcHJvdG9fXzogW10gfSBpbnN0YW5jZW9mIEFycmF5ICYmIGZ1bmN0aW9uIChkLCBiKSB7IGQuX19wcm90b19fID0gYjsgfSkgfHxcbiAgICAgICAgICAgIGZ1bmN0aW9uIChkLCBiKSB7IGZvciAodmFyIHAgaW4gYikgaWYgKGIuaGFzT3duUHJvcGVydHkocCkpIGRbcF0gPSBiW3BdOyB9O1xuICAgICAgICByZXR1cm4gZXh0ZW5kU3RhdGljcyhkLCBiKTtcbiAgICB9XG4gICAgcmV0dXJuIGZ1bmN0aW9uIChkLCBiKSB7XG4gICAgICAgIGV4dGVuZFN0YXRpY3MoZCwgYik7XG4gICAgICAgIGZ1bmN0aW9uIF9fKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gZDsgfVxuICAgICAgICBkLnByb3RvdHlwZSA9IGIgPT09IG51bGwgPyBPYmplY3QuY3JlYXRlKGIpIDogKF9fLnByb3RvdHlwZSA9IGIucHJvdG90eXBlLCBuZXcgX18oKSk7XG4gICAgfTtcbn0pKCk7XG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG4vLy8gPHJlZmVyZW5jZSBwYXRoPScuLi8uLi90eXBlcy9hbWJpZW50L291dGxpbmVQbHVnaW4uZC50cycvPlxuLy8vIDxyZWZlcmVuY2UgcGF0aD0nLi4vLi4vdHlwZXMvYW1iaWVudC93ZWJpbnRlbnRzLmQudHMnLz5cbnZhciBSYXZlbiA9IHJlcXVpcmUoXCJyYXZlbi1qc1wiKTtcbnZhciBjbGlwYm9hcmRfMSA9IHJlcXVpcmUoXCIuL2NsaXBib2FyZFwiKTtcbnZhciBlcnJvcl9yZXBvcnRlcl8xID0gcmVxdWlyZShcIi4vZXJyb3JfcmVwb3J0ZXJcIik7XG52YXIgZmFrZV9jb25uZWN0aW9uXzEgPSByZXF1aXJlKFwiLi9mYWtlX2Nvbm5lY3Rpb25cIik7XG52YXIgbWFpbl8xID0gcmVxdWlyZShcIi4vbWFpblwiKTtcbnZhciBvdXRsaW5lX3NlcnZlcl8xID0gcmVxdWlyZShcIi4vb3V0bGluZV9zZXJ2ZXJcIik7XG52YXIgdXBkYXRlcl8xID0gcmVxdWlyZShcIi4vdXBkYXRlclwiKTtcbnZhciBpbnRlcmNlcHRvcnMgPSByZXF1aXJlKFwiLi91cmxfaW50ZXJjZXB0b3JcIik7XG4vLyBQdXNoZXMgYSBjbGlwYm9hcmQgZXZlbnQgd2hlbmV2ZXIgdGhlIGFwcCBpcyBicm91Z2h0IHRvIHRoZSBmb3JlZ3JvdW5kLlxudmFyIENvcmRvdmFDbGlwYm9hcmQgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKENvcmRvdmFDbGlwYm9hcmQsIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gQ29yZG92YUNsaXBib2FyZCgpIHtcbiAgICAgICAgdmFyIF90aGlzID0gX3N1cGVyLmNhbGwodGhpcykgfHwgdGhpcztcbiAgICAgICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigncmVzdW1lJywgX3RoaXMuZW1pdEV2ZW50LmJpbmQoX3RoaXMpKTtcbiAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgIH1cbiAgICBDb3Jkb3ZhQ2xpcGJvYXJkLnByb3RvdHlwZS5nZXRDb250ZW50cyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICAgICAgICAgIGNvcmRvdmEucGx1Z2lucy5jbGlwYm9hcmQucGFzdGUocmVzb2x2ZSwgcmVqZWN0KTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICByZXR1cm4gQ29yZG92YUNsaXBib2FyZDtcbn0oY2xpcGJvYXJkXzEuQWJzdHJhY3RDbGlwYm9hcmQpKTtcbi8vIEFkZHMgcmVwb3J0cyBmcm9tIHRoZSAobmF0aXZlKSBDb3Jkb3ZhIHBsdWdpbi5cbnZhciBDb3Jkb3ZhRXJyb3JSZXBvcnRlciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoQ29yZG92YUVycm9yUmVwb3J0ZXIsIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gQ29yZG92YUVycm9yUmVwb3J0ZXIoYXBwVmVyc2lvbiwgYXBwQnVpbGROdW1iZXIsIGRzbiwgbmF0aXZlRHNuKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IF9zdXBlci5jYWxsKHRoaXMsIGFwcFZlcnNpb24sIGRzbiwgeyAnYnVpbGQubnVtYmVyJzogYXBwQnVpbGROdW1iZXIgfSkgfHwgdGhpcztcbiAgICAgICAgY29yZG92YS5wbHVnaW5zLm91dGxpbmUubG9nLmluaXRpYWxpemUobmF0aXZlRHNuKS5jYXRjaChjb25zb2xlLmVycm9yKTtcbiAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgIH1cbiAgICBDb3Jkb3ZhRXJyb3JSZXBvcnRlci5wcm90b3R5cGUucmVwb3J0ID0gZnVuY3Rpb24gKHVzZXJGZWVkYmFjaywgZmVlZGJhY2tDYXRlZ29yeSwgdXNlckVtYWlsKSB7XG4gICAgICAgIHJldHVybiBfc3VwZXIucHJvdG90eXBlLnJlcG9ydC5jYWxsKHRoaXMsIHVzZXJGZWVkYmFjaywgZmVlZGJhY2tDYXRlZ29yeSwgdXNlckVtYWlsKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiBjb3Jkb3ZhLnBsdWdpbnMub3V0bGluZS5sb2cuc2VuZChSYXZlbi5sYXN0RXZlbnRJZCgpKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICByZXR1cm4gQ29yZG92YUVycm9yUmVwb3J0ZXI7XG59KGVycm9yX3JlcG9ydGVyXzEuU2VudHJ5RXJyb3JSZXBvcnRlcikpO1xuZXhwb3J0cy5Db3Jkb3ZhRXJyb3JSZXBvcnRlciA9IENvcmRvdmFFcnJvclJlcG9ydGVyO1xuLy8gVGhpcyBjbGFzcyBzaG91bGQgb25seSBiZSBpbnN0YW50aWF0ZWQgYWZ0ZXIgQ29yZG92YSBmaXJlcyB0aGUgZGV2aWNlcmVhZHkgZXZlbnQuXG52YXIgQ29yZG92YVBsYXRmb3JtID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIENvcmRvdmFQbGF0Zm9ybSgpIHtcbiAgICB9XG4gICAgQ29yZG92YVBsYXRmb3JtLmlzQnJvd3NlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIGRldmljZS5wbGF0Zm9ybSA9PT0gJ2Jyb3dzZXInO1xuICAgIH07XG4gICAgQ29yZG92YVBsYXRmb3JtLnByb3RvdHlwZS5oYXNEZXZpY2VTdXBwb3J0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gIUNvcmRvdmFQbGF0Zm9ybS5pc0Jyb3dzZXIoKTtcbiAgICB9O1xuICAgIENvcmRvdmFQbGF0Zm9ybS5wcm90b3R5cGUuZ2V0UGVyc2lzdGVudFNlcnZlckZhY3RvcnkgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHJldHVybiBmdW5jdGlvbiAoc2VydmVySWQsIGNvbmZpZywgZXZlbnRRdWV1ZSkge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBvdXRsaW5lX3NlcnZlcl8xLk91dGxpbmVTZXJ2ZXIoc2VydmVySWQsIGNvbmZpZywgX3RoaXMuaGFzRGV2aWNlU3VwcG9ydCgpID8gbmV3IGNvcmRvdmEucGx1Z2lucy5vdXRsaW5lLkNvbm5lY3Rpb24oY29uZmlnLCBzZXJ2ZXJJZCkgOlxuICAgICAgICAgICAgICAgIG5ldyBmYWtlX2Nvbm5lY3Rpb25fMS5GYWtlT3V0bGluZUNvbm5lY3Rpb24oY29uZmlnLCBzZXJ2ZXJJZCksIGV2ZW50UXVldWUpO1xuICAgICAgICB9O1xuICAgIH07XG4gICAgQ29yZG92YVBsYXRmb3JtLnByb3RvdHlwZS5nZXRVcmxJbnRlcmNlcHRvciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKGRldmljZS5wbGF0Zm9ybSA9PT0gJ2lPUycgfHwgZGV2aWNlLnBsYXRmb3JtID09PSAnTWFjIE9TIFgnKSB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IGludGVyY2VwdG9ycy5BcHBsZVVybEludGVyY2VwdG9yKGFwcGxlTGF1bmNoVXJsKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChkZXZpY2UucGxhdGZvcm0gPT09ICdBbmRyb2lkJykge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBpbnRlcmNlcHRvcnMuQW5kcm9pZFVybEludGVyY2VwdG9yKCk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc29sZS53YXJuKCdubyBpbnRlbnQgaW50ZXJjZXB0b3IgYXZhaWxhYmxlJyk7XG4gICAgICAgIHJldHVybiBuZXcgaW50ZXJjZXB0b3JzLlVybEludGVyY2VwdG9yKCk7XG4gICAgfTtcbiAgICBDb3Jkb3ZhUGxhdGZvcm0ucHJvdG90eXBlLmdldENsaXBib2FyZCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBDb3Jkb3ZhQ2xpcGJvYXJkKCk7XG4gICAgfTtcbiAgICBDb3Jkb3ZhUGxhdGZvcm0ucHJvdG90eXBlLmdldEVycm9yUmVwb3J0ZXIgPSBmdW5jdGlvbiAoZW52KSB7XG4gICAgICAgIHJldHVybiB0aGlzLmhhc0RldmljZVN1cHBvcnQoKSA/XG4gICAgICAgICAgICBuZXcgQ29yZG92YUVycm9yUmVwb3J0ZXIoZW52LkFQUF9WRVJTSU9OLCBlbnYuQVBQX0JVSUxEX05VTUJFUiwgZW52LlNFTlRSWV9EU04sIGVudi5TRU5UUllfTkFUSVZFX0RTTikgOlxuICAgICAgICAgICAgbmV3IGVycm9yX3JlcG9ydGVyXzEuU2VudHJ5RXJyb3JSZXBvcnRlcihlbnYuQVBQX1ZFUlNJT04sIGVudi5TRU5UUllfRFNOLCB7fSk7XG4gICAgfTtcbiAgICBDb3Jkb3ZhUGxhdGZvcm0ucHJvdG90eXBlLmdldFVwZGF0ZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBuZXcgdXBkYXRlcl8xLkFic3RyYWN0VXBkYXRlcigpO1xuICAgIH07XG4gICAgQ29yZG92YVBsYXRmb3JtLnByb3RvdHlwZS5xdWl0QXBwbGljYXRpb24gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIC8vIE9ubHkgdXNlZCBpbiBtYWNPUyBiZWNhdXNlIG1lbnUgYmFyIGFwcHMgcHJvdmlkZSBubyBhbHRlcm5hdGl2ZSB3YXkgb2YgcXVpdHRpbmcuXG4gICAgICAgIGNvcmRvdmEucGx1Z2lucy5vdXRsaW5lLnF1aXRBcHBsaWNhdGlvbigpO1xuICAgIH07XG4gICAgcmV0dXJuIENvcmRvdmFQbGF0Zm9ybTtcbn0oKSk7XG4vLyBodHRwczovL2NvcmRvdmEuYXBhY2hlLm9yZy9kb2NzL2VuL2xhdGVzdC9jb3Jkb3ZhL2V2ZW50cy9ldmVudHMuaHRtbCNkZXZpY2VyZWFkeVxudmFyIG9uY2VEZXZpY2VSZWFkeSA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlKSB7XG4gICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignZGV2aWNlcmVhZHknLCByZXNvbHZlKTtcbn0pO1xuLy8gY29yZG92YS1baW9zfG9zeF0gY2FsbCBhIGdsb2JhbCBmdW5jdGlvbiB3aXRoIHRoaXMgc2lnbmF0dXJlIHdoZW4gYSBVUkwgaXNcbi8vIGludGVyY2VwdGVkLiBXZSBoYW5kbGUgVVJMIGludGVyY2VwdGlvbnMgd2l0aCBhbiBpbnRlbnQgaW50ZXJjZXB0b3I7IGhvd2V2ZXIsXG4vLyB3aGVuIHRoZSBhcHAgaXMgbGF1bmNoZWQgdmlhIFVSTCBvdXIgc3RhcnQgdXAgc2VxdWVuY2UgbWlzc2VzIHRoZSBjYWxsIGR1ZSB0b1xuLy8gYSByYWNlLiBEZWZpbmUgdGhlIGZ1bmN0aW9uIHRlbXBvcmFyaWx5IGhlcmUsIGFuZCBzZXQgYSBnbG9iYWwgdmFyaWFibGUuXG52YXIgYXBwbGVMYXVuY2hVcmw7XG53aW5kb3cuaGFuZGxlT3BlblVSTCA9IGZ1bmN0aW9uICh1cmwpIHtcbiAgICBhcHBsZUxhdW5jaFVybCA9IHVybDtcbn07XG5vbmNlRGV2aWNlUmVhZHkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgbWFpbl8xLm1haW4obmV3IENvcmRvdmFQbGF0Zm9ybSgpKTtcbn0pO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgMjAxOCBUaGUgT3V0bGluZSBBdXRob3JzXG4vL1xuLy8gTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbi8vIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuLy9cbi8vICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4vL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuLy8gZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4vLyBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbi8vIEtlZXAgdGhlc2UgaW4gc3luYyB3aXRoIHRoZSBFbnZpcm9ubWVudFZhcmlhYmxlcyBpbnRlcmZhY2UgYWJvdmUuXG52YXIgRU5WX0tFWVMgPSB7XG4gICAgQVBQX1ZFUlNJT046ICdBUFBfVkVSU0lPTicsXG4gICAgQVBQX0JVSUxEX05VTUJFUjogJ0FQUF9CVUlMRF9OVU1CRVInLFxuICAgIFNFTlRSWV9EU046ICdTRU5UUllfRFNOJyxcbiAgICBTRU5UUllfTkFUSVZFX0RTTjogJ1NFTlRSWV9OQVRJVkVfRFNOJ1xufTtcbmZ1bmN0aW9uIHZhbGlkYXRlRW52VmFycyhqc29uKSB7XG4gICAgZm9yICh2YXIga2V5IGluIEVOVl9LRVlTKSB7XG4gICAgICAgIGlmICghanNvbi5oYXNPd25Qcm9wZXJ0eShrZXkpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJNaXNzaW5nIGVudmlyb25tZW50IHZhcmlhYmxlOiBcIiArIGtleSk7XG4gICAgICAgIH1cbiAgICB9XG59XG4vLyBBY2NvcmRpbmcgdG8gaHR0cDovL2Nhbml1c2UuY29tLyNmZWF0PWZldGNoIGZldGNoIGRpZG4ndCBoaXQgaU9TIFNhZmFyaVxuLy8gdW50aWwgdjEwLjMgcmVsZWFzZWQgMy8yNi8xNywgc28gdXNlIFhNTEh0dHBSZXF1ZXN0IGluc3RlYWQuXG5leHBvcnRzLm9uY2VFbnZWYXJzID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgIHZhciB4aHIgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtcbiAgICB4aHIub25sb2FkID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgdmFyIGpzb24gPSBKU09OLnBhcnNlKHhoci5yZXNwb25zZVRleHQpO1xuICAgICAgICAgICAgdmFsaWRhdGVFbnZWYXJzKGpzb24pO1xuICAgICAgICAgICAgY29uc29sZS5kZWJ1ZygnUmVzb2x2aW5nIHdpdGggZW52VmFyczonLCBqc29uKTtcbiAgICAgICAgICAgIHJlc29sdmUoanNvbik7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGVycikge1xuICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIHhoci5vcGVuKCdHRVQnLCAnZW52aXJvbm1lbnQuanNvbicsIHRydWUpO1xuICAgIHhoci5zZW5kKCk7XG59KTtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG52YXIgUmF2ZW4gPSByZXF1aXJlKFwicmF2ZW4tanNcIik7XG52YXIgU2VudHJ5RXJyb3JSZXBvcnRlciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBTZW50cnlFcnJvclJlcG9ydGVyKGFwcFZlcnNpb24sIGRzbiwgdGFncykge1xuICAgICAgICBSYXZlbi5jb25maWcoZHNuLCB7IHJlbGVhc2U6IGFwcFZlcnNpb24sICd0YWdzJzogdGFncyB9KS5pbnN0YWxsKCk7XG4gICAgICAgIHRoaXMuc2V0VXBVbmhhbmRsZWRSZWplY3Rpb25MaXN0ZW5lcigpO1xuICAgIH1cbiAgICBTZW50cnlFcnJvclJlcG9ydGVyLnByb3RvdHlwZS5yZXBvcnQgPSBmdW5jdGlvbiAodXNlckZlZWRiYWNrLCBmZWVkYmFja0NhdGVnb3J5LCB1c2VyRW1haWwpIHtcbiAgICAgICAgUmF2ZW4uc2V0VXNlckNvbnRleHQoeyBlbWFpbDogdXNlckVtYWlsIHx8ICcnIH0pO1xuICAgICAgICBSYXZlbi5jYXB0dXJlTWVzc2FnZSh1c2VyRmVlZGJhY2ssIHsgdGFnczogeyBjYXRlZ29yeTogZmVlZGJhY2tDYXRlZ29yeSB9IH0pO1xuICAgICAgICBSYXZlbi5zZXRVc2VyQ29udGV4dCgpOyAvLyBSZXNldCB0aGUgdXNlciBjb250ZXh0LCBkb24ndCBjYWNoZSB0aGUgZW1haWxcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgIH07XG4gICAgU2VudHJ5RXJyb3JSZXBvcnRlci5wcm90b3R5cGUuc2V0VXBVbmhhbmRsZWRSZWplY3Rpb25MaXN0ZW5lciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgLy8gQ2hyb21lIGlzIHRoZSBvbmx5IGJyb3dzZXIgdGhhdCBzdXBwb3J0cyB0aGUgdW5oYW5kbGVkcmVqZWN0aW9uIGV2ZW50LlxuICAgICAgICAvLyBUaGlzIGlzIGZpbmUgZm9yIEFuZHJvaWQsIGJ1dCB3aWxsIG5vdCB3b3JrIGluIGlPUy5cbiAgICAgICAgdmFyIHVuaGFuZGxlZFJlamVjdGlvbiA9ICd1bmhhbmRsZWRyZWplY3Rpb24nO1xuICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcih1bmhhbmRsZWRSZWplY3Rpb24sIGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICAgICAgdmFyIHJlYXNvbiA9IGV2ZW50LnJlYXNvbjtcbiAgICAgICAgICAgIHZhciBtc2cgPSByZWFzb24uc3RhY2sgPyByZWFzb24uc3RhY2sgOiByZWFzb247XG4gICAgICAgICAgICBSYXZlbi5jYXB0dXJlQnJlYWRjcnVtYih7IG1lc3NhZ2U6IG1zZywgY2F0ZWdvcnk6IHVuaGFuZGxlZFJlamVjdGlvbiB9KTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICByZXR1cm4gU2VudHJ5RXJyb3JSZXBvcnRlcjtcbn0oKSk7XG5leHBvcnRzLlNlbnRyeUVycm9yUmVwb3J0ZXIgPSBTZW50cnlFcnJvclJlcG9ydGVyO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgMjAxOCBUaGUgT3V0bGluZSBBdXRob3JzXG4vL1xuLy8gTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbi8vIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuLy9cbi8vICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4vL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuLy8gZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4vLyBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbi8vLyA8cmVmZXJlbmNlIHBhdGg9Jy4uLy4uL3R5cGVzL2FtYmllbnQvb3V0bGluZVBsdWdpbi5kLnRzJy8+XG52YXIgZXJyb3JzID0gcmVxdWlyZShcIi4uL21vZGVsL2Vycm9yc1wiKTtcbi8vIE5vdGUgdGhhdCBiZWNhdXNlIHRoaXMgaW1wbGVtZW50YXRpb24gZG9lcyBub3QgZW1pdCBkaXNjb25uZWN0aW9uIGV2ZW50cywgXCJzd2l0Y2hpbmdcIiBiZXR3ZWVuXG4vLyBzZXJ2ZXJzIGluIHRoZSBzZXJ2ZXIgbGlzdCB3aWxsIG5vdCB3b3JrIGFzIGV4cGVjdGVkLlxudmFyIEZha2VPdXRsaW5lQ29ubmVjdGlvbiA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBGYWtlT3V0bGluZUNvbm5lY3Rpb24oY29uZmlnLCBpZCkge1xuICAgICAgICB0aGlzLmNvbmZpZyA9IGNvbmZpZztcbiAgICAgICAgdGhpcy5pZCA9IGlkO1xuICAgICAgICB0aGlzLnJ1bm5pbmcgPSBmYWxzZTtcbiAgICB9XG4gICAgRmFrZU91dGxpbmVDb25uZWN0aW9uLnByb3RvdHlwZS5wbGF5QnJva2VuID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gdGhpcy5jb25maWcubmFtZSAmJiB0aGlzLmNvbmZpZy5uYW1lLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMoJ2Jyb2tlbicpO1xuICAgIH07XG4gICAgRmFrZU91dGxpbmVDb25uZWN0aW9uLnByb3RvdHlwZS5wbGF5VW5yZWFjaGFibGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiAhKHRoaXMuY29uZmlnLm5hbWUgJiYgdGhpcy5jb25maWcubmFtZS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKCd1bnJlYWNoYWJsZScpKTtcbiAgICB9O1xuICAgIEZha2VPdXRsaW5lQ29ubmVjdGlvbi5wcm90b3R5cGUuc3RhcnQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmICh0aGlzLnJ1bm5pbmcpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXRoaXMucGxheVVucmVhY2hhYmxlKCkpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgZXJyb3JzLk91dGxpbmVQbHVnaW5FcnJvcig1IC8qIFNFUlZFUl9VTlJFQUNIQUJMRSAqLykpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHRoaXMucGxheUJyb2tlbigpKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IGVycm9ycy5PdXRsaW5lUGx1Z2luRXJyb3IoOCAvKiBTSEFET1dTT0NLU19TVEFSVF9GQUlMVVJFICovKSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB0aGlzLnJ1bm5pbmcgPSB0cnVlO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICBGYWtlT3V0bGluZUNvbm5lY3Rpb24ucHJvdG90eXBlLnN0b3AgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmICghdGhpcy5ydW5uaW5nKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5ydW5uaW5nID0gZmFsc2U7XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICB9O1xuICAgIEZha2VPdXRsaW5lQ29ubmVjdGlvbi5wcm90b3R5cGUuaXNSdW5uaW5nID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMucnVubmluZyk7XG4gICAgfTtcbiAgICBGYWtlT3V0bGluZUNvbm5lY3Rpb24ucHJvdG90eXBlLmlzUmVhY2hhYmxlID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCF0aGlzLnBsYXlVbnJlYWNoYWJsZSgpKTtcbiAgICB9O1xuICAgIEZha2VPdXRsaW5lQ29ubmVjdGlvbi5wcm90b3R5cGUub25TdGF0dXNDaGFuZ2UgPSBmdW5jdGlvbiAobGlzdGVuZXIpIHtcbiAgICAgICAgLy8gTk9PUFxuICAgIH07XG4gICAgcmV0dXJuIEZha2VPdXRsaW5lQ29ubmVjdGlvbjtcbn0oKSk7XG5leHBvcnRzLkZha2VPdXRsaW5lQ29ubmVjdGlvbiA9IEZha2VPdXRsaW5lQ29ubmVjdGlvbjtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG52YXIgX19yZWFkID0gKHRoaXMgJiYgdGhpcy5fX3JlYWQpIHx8IGZ1bmN0aW9uIChvLCBuKSB7XG4gICAgdmFyIG0gPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgb1tTeW1ib2wuaXRlcmF0b3JdO1xuICAgIGlmICghbSkgcmV0dXJuIG87XG4gICAgdmFyIGkgPSBtLmNhbGwobyksIHIsIGFyID0gW10sIGU7XG4gICAgdHJ5IHtcbiAgICAgICAgd2hpbGUgKChuID09PSB2b2lkIDAgfHwgbi0tID4gMCkgJiYgIShyID0gaS5uZXh0KCkpLmRvbmUpIGFyLnB1c2goci52YWx1ZSk7XG4gICAgfVxuICAgIGNhdGNoIChlcnJvcikgeyBlID0geyBlcnJvcjogZXJyb3IgfTsgfVxuICAgIGZpbmFsbHkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgaWYgKHIgJiYgIXIuZG9uZSAmJiAobSA9IGlbXCJyZXR1cm5cIl0pKSBtLmNhbGwoaSk7XG4gICAgICAgIH1cbiAgICAgICAgZmluYWxseSB7IGlmIChlKSB0aHJvdyBlLmVycm9yOyB9XG4gICAgfVxuICAgIHJldHVybiBhcjtcbn07XG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG52YXIgdXJsID0gcmVxdWlyZShcInVybFwiKTtcbnZhciBldmVudHNfMSA9IHJlcXVpcmUoXCIuLi9tb2RlbC9ldmVudHNcIik7XG52YXIgYXBwXzEgPSByZXF1aXJlKFwiLi9hcHBcIik7XG52YXIgZW52aXJvbm1lbnRfMSA9IHJlcXVpcmUoXCIuL2Vudmlyb25tZW50XCIpO1xudmFyIHBlcnNpc3RlbnRfc2VydmVyXzEgPSByZXF1aXJlKFwiLi9wZXJzaXN0ZW50X3NlcnZlclwiKTtcbnZhciBzZXR0aW5nc18xID0gcmVxdWlyZShcIi4vc2V0dGluZ3NcIik7XG4vLyBVc2VkIHRvIGRldGVybWluZSB3aGV0aGVyIHRvIHVzZSBQb2x5bWVyIGZ1bmN0aW9uYWxpdHkgb24gYXBwIGluaXRpYWxpemF0aW9uIGZhaWx1cmUuXG52YXIgd2ViQ29tcG9uZW50c0FyZVJlYWR5ID0gZmFsc2U7XG5kb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdXZWJDb21wb25lbnRzUmVhZHknLCBmdW5jdGlvbiAoKSB7XG4gICAgY29uc29sZS5kZWJ1ZygncmVjZWl2ZWQgV2ViQ29tcG9uZW50c1JlYWR5IGV2ZW50Jyk7XG4gICAgd2ViQ29tcG9uZW50c0FyZVJlYWR5ID0gdHJ1ZTtcbn0pO1xuLy8gVXNlZCB0byBkZWxheSBsb2FkaW5nIHRoZSBhcHAgdW50aWwgKHRyYW5zbGF0aW9uKSByZXNvdXJjZXMgaGF2ZSBiZWVuIGxvYWRlZC4gVGhpcyBjYW4gaGFwcGVuIGFcbi8vIGxpdHRsZSBsYXRlciB0aGFuIFdlYkNvbXBvbmVudHNSZWFkeS5cbnZhciBvbmNlUG9seW1lcklzUmVhZHkgPSBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSkge1xuICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2FwcC1sb2NhbGl6ZS1yZXNvdXJjZXMtbG9hZGVkJywgZnVuY3Rpb24gKCkge1xuICAgICAgICBjb25zb2xlLmRlYnVnKCdyZWNlaXZlZCBhcHAtbG9jYWxpemUtcmVzb3VyY2VzLWxvYWRlZCBldmVudCcpO1xuICAgICAgICByZXNvbHZlKCk7XG4gICAgfSk7XG59KTtcbi8vIEhlbHBlcnNcbi8vIERvIG5vdCBjYWxsIHVudGlsIFdlYkNvbXBvbmVudHNSZWFkeSBoYXMgZmlyZWQhXG5mdW5jdGlvbiBnZXRSb290RWwoKSB7XG4gICAgcmV0dXJuIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ2FwcC1yb290Jyk7XG59XG5mdW5jdGlvbiBjcmVhdGVTZXJ2ZXJSZXBvKGV2ZW50UXVldWUsIHN0b3JhZ2UsIGRldmljZVN1cHBvcnQsIGNvbm5lY3Rpb25UeXBlKSB7XG4gICAgdmFyIHJlcG8gPSBuZXcgcGVyc2lzdGVudF9zZXJ2ZXJfMS5QZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeShjb25uZWN0aW9uVHlwZSwgZXZlbnRRdWV1ZSwgc3RvcmFnZSk7XG4gICAgaWYgKCFkZXZpY2VTdXBwb3J0KSB7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ0RldGVjdGVkIGRldmVsb3BtZW50IGVudmlyb25tZW50LCB1c2luZyBmYWtlIHNlcnZlcnMuJyk7XG4gICAgICAgIGlmIChyZXBvLmdldEFsbCgpLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICAgICAgcmVwby5hZGQoeyBuYW1lOiAnRmFrZSBXb3JraW5nIFNlcnZlcicsIGhvc3Q6ICcxMjcuMC4wLjEnIH0pO1xuICAgICAgICAgICAgcmVwby5hZGQoeyBuYW1lOiAnRmFrZSBCcm9rZW4gU2VydmVyJywgaG9zdDogJzE5Mi4wLjIuMScgfSk7XG4gICAgICAgICAgICByZXBvLmFkZCh7IG5hbWU6ICdGYWtlIFVucmVhY2hhYmxlIFNlcnZlcicsIGhvc3Q6ICcxMC4wLjAuMjQnIH0pO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiByZXBvO1xufVxuZnVuY3Rpb24gbWFpbihwbGF0Zm9ybSkge1xuICAgIHJldHVybiBQcm9taXNlLmFsbChbZW52aXJvbm1lbnRfMS5vbmNlRW52VmFycywgb25jZVBvbHltZXJJc1JlYWR5XSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKF9hKSB7XG4gICAgICAgIHZhciBfYiA9IF9fcmVhZChfYSwgMSksIGVudmlyb25tZW50VmFycyA9IF9iWzBdO1xuICAgICAgICBjb25zb2xlLmRlYnVnKCdydW5uaW5nIG1haW4oKSBmdW5jdGlvbicpO1xuICAgICAgICB2YXIgcXVlcnlQYXJhbXMgPSB1cmwucGFyc2UoZG9jdW1lbnQuVVJMLCB0cnVlKS5xdWVyeTtcbiAgICAgICAgdmFyIGRlYnVnTW9kZSA9IHF1ZXJ5UGFyYW1zLmRlYnVnID09PSAndHJ1ZSc7XG4gICAgICAgIHZhciBldmVudFF1ZXVlID0gbmV3IGV2ZW50c18xLkV2ZW50UXVldWUoKTtcbiAgICAgICAgdmFyIHNlcnZlclJlcG8gPSBjcmVhdGVTZXJ2ZXJSZXBvKGV2ZW50UXVldWUsIHdpbmRvdy5sb2NhbFN0b3JhZ2UsIHBsYXRmb3JtLmhhc0RldmljZVN1cHBvcnQoKSwgcGxhdGZvcm0uZ2V0UGVyc2lzdGVudFNlcnZlckZhY3RvcnkoKSk7XG4gICAgICAgIHZhciBzZXR0aW5ncyA9IG5ldyBzZXR0aW5nc18xLlNldHRpbmdzKCk7XG4gICAgICAgIHZhciBhcHAgPSBuZXcgYXBwXzEuQXBwKGV2ZW50UXVldWUsIHNlcnZlclJlcG8sIGdldFJvb3RFbCgpLCBkZWJ1Z01vZGUsIHBsYXRmb3JtLmdldFVybEludGVyY2VwdG9yKCksIHBsYXRmb3JtLmdldENsaXBib2FyZCgpLCBwbGF0Zm9ybS5nZXRFcnJvclJlcG9ydGVyKGVudmlyb25tZW50VmFycyksIHNldHRpbmdzLCBlbnZpcm9ubWVudFZhcnMsIHBsYXRmb3JtLmdldFVwZGF0ZXIoKSwgcGxhdGZvcm0ucXVpdEFwcGxpY2F0aW9uKTtcbiAgICB9LCBmdW5jdGlvbiAoZSkge1xuICAgICAgICBvblVuZXhwZWN0ZWRFcnJvcihlKTtcbiAgICAgICAgdGhyb3cgZTtcbiAgICB9KTtcbn1cbmV4cG9ydHMubWFpbiA9IG1haW47XG5mdW5jdGlvbiBvblVuZXhwZWN0ZWRFcnJvcihlcnJvcikge1xuICAgIHZhciByb290RWwgPSBnZXRSb290RWwoKTtcbiAgICBpZiAod2ViQ29tcG9uZW50c0FyZVJlYWR5ICYmIHJvb3RFbCAmJiByb290RWwubG9jYWxpemUpIHtcbiAgICAgICAgdmFyIGxvY2FsaXplID0gcm9vdEVsLmxvY2FsaXplLmJpbmQocm9vdEVsKTtcbiAgICAgICAgcm9vdEVsLnNob3dUb2FzdChsb2NhbGl6ZSgnZXJyb3ItdW5leHBlY3RlZCcpLCAxMjAwMDApO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgLy8gU29tZXRoaW5nIHdlbnQgdGVycmlibHkgd3JvbmcgKGkuZS4gUG9seW1lciBmYWlsZWQgdG8gaW5pdGlhbGl6ZSkuIFByb3ZpZGUgc29tZSBtZXNzYWdpbmcgdG9cbiAgICAgICAgLy8gdGhlIHVzZXIsIGV2ZW4gaWYgd2UgYXJlIG5vdCBhYmxlIHRvIGRpc3BsYXkgaXQgaW4gYSB0b2FzdCBvciBsb2NhbGl6ZSBpdC5cbiAgICAgICAgLy8gVE9ETzogcHJvdmlkZSBhbiBoZWxwIGVtYWlsIG9uY2Ugd2UgaGF2ZSBhIGRvbWFpbi5cbiAgICAgICAgYWxlcnQoXCJBbiB1bmV4cGVjdGVkIGVycm9yIG9jY3VycmVkLlwiKTtcbiAgICB9XG4gICAgY29uc29sZS5lcnJvcihlcnJvcik7XG59XG4vLyBSZXR1cm5zIFBvbHltZXIncyBsb2NhbGl6YXRpb24gZnVuY3Rpb24uIE11c3QgYmUgY2FsbGVkIGFmdGVyIFdlYkNvbXBvbmVudHNSZWFkeSBoYXMgZmlyZWQuXG5mdW5jdGlvbiBnZXRMb2NhbGl6YXRpb25GdW5jdGlvbigpIHtcbiAgICB2YXIgcm9vdEVsID0gZ2V0Um9vdEVsKCk7XG4gICAgaWYgKCFyb290RWwpIHtcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiByb290RWwubG9jYWxpemU7XG59XG5leHBvcnRzLmdldExvY2FsaXphdGlvbkZ1bmN0aW9uID0gZ2V0TG9jYWxpemF0aW9uRnVuY3Rpb247XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxuT2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFwiX19lc01vZHVsZVwiLCB7IHZhbHVlOiB0cnVlIH0pO1xuLy8vIDxyZWZlcmVuY2UgcGF0aD0nLi4vLi4vdHlwZXMvYW1iaWVudC9vdXRsaW5lUGx1Z2luLmQudHMnLz5cbnZhciBlcnJvcnMgPSByZXF1aXJlKFwiLi4vbW9kZWwvZXJyb3JzXCIpO1xudmFyIGV2ZW50cyA9IHJlcXVpcmUoXCIuLi9tb2RlbC9ldmVudHNcIik7XG52YXIgT3V0bGluZVNlcnZlciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBPdXRsaW5lU2VydmVyKGlkLCBjb25maWcsIGNvbm5lY3Rpb24sIGV2ZW50UXVldWUpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgdGhpcy5pZCA9IGlkO1xuICAgICAgICB0aGlzLmNvbmZpZyA9IGNvbmZpZztcbiAgICAgICAgdGhpcy5jb25uZWN0aW9uID0gY29ubmVjdGlvbjtcbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlID0gZXZlbnRRdWV1ZTtcbiAgICAgICAgdGhpcy5jb25uZWN0aW9uLm9uU3RhdHVzQ2hhbmdlKGZ1bmN0aW9uIChzdGF0dXMpIHtcbiAgICAgICAgICAgIHZhciBzdGF0dXNFdmVudDtcbiAgICAgICAgICAgIHN3aXRjaCAoc3RhdHVzKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAwIC8qIENPTk5FQ1RFRCAqLzpcbiAgICAgICAgICAgICAgICAgICAgc3RhdHVzRXZlbnQgPSBuZXcgZXZlbnRzLlNlcnZlckNvbm5lY3RlZChfdGhpcyk7XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgMSAvKiBESVNDT05ORUNURUQgKi86XG4gICAgICAgICAgICAgICAgICAgIHN0YXR1c0V2ZW50ID0gbmV3IGV2ZW50cy5TZXJ2ZXJEaXNjb25uZWN0ZWQoX3RoaXMpO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlIDIgLyogUkVDT05ORUNUSU5HICovOlxuICAgICAgICAgICAgICAgICAgICBzdGF0dXNFdmVudCA9IG5ldyBldmVudHMuU2VydmVyUmVjb25uZWN0aW5nKF90aGlzKTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgY29uc29sZS53YXJuKFwiUmVjZWl2ZWQgdW5rbm93biBjb25uZWN0aW9uIHN0YXR1cyBcIiArIHN0YXR1cyk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGV2ZW50UXVldWUuZW5xdWV1ZShzdGF0dXNFdmVudCk7XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoT3V0bGluZVNlcnZlci5wcm90b3R5cGUsIFwibmFtZVwiLCB7XG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuY29uZmlnLm5hbWUgfHwgdGhpcy5jb25maWcuaG9zdCB8fCAnJztcbiAgICAgICAgfSxcbiAgICAgICAgc2V0OiBmdW5jdGlvbiAobmV3TmFtZSkge1xuICAgICAgICAgICAgdGhpcy5jb25maWcubmFtZSA9IG5ld05hbWU7XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IHRydWUsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShPdXRsaW5lU2VydmVyLnByb3RvdHlwZSwgXCJob3N0XCIsIHtcbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5jb25maWcuaG9zdDtcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogdHJ1ZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT3V0bGluZVNlcnZlci5wcm90b3R5cGUuY29ubmVjdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY29ubmVjdGlvbi5zdGFydCgpLmNhdGNoKGZ1bmN0aW9uIChlKSB7XG4gICAgICAgICAgICAvLyBlIG9yaWdpbmF0ZXMgaW4gXCJuYXRpdmVcIiBjb2RlOiBlaXRoZXIgQ29yZG92YSBvciBFbGVjdHJvbidzIG1haW4gcHJvY2Vzcy5cbiAgICAgICAgICAgIC8vIEJlY2F1c2Ugb2YgdGhpcywgd2UgY2Fubm90IGFzc3VtZSBcImluc3RhbmNlb2YgT3V0bGluZVBsdWdpbkVycm9yXCIgd2lsbCB3b3JrLlxuICAgICAgICAgICAgaWYgKGUuZXJyb3JDb2RlKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgZXJyb3JzLmZyb21FcnJvckNvZGUoZS5lcnJvckNvZGUpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdGhyb3cgZTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBPdXRsaW5lU2VydmVyLnByb3RvdHlwZS5kaXNjb25uZWN0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gdGhpcy5jb25uZWN0aW9uLnN0b3AoKS5jYXRjaChmdW5jdGlvbiAoZSkge1xuICAgICAgICAgICAgLy8gVE9ETzogTm9uZSBvZiB0aGUgcGx1Z2lucyBjdXJyZW50bHkgcmV0dXJuIGFuIEVycm9yQ29kZSBvbiBkaXNjb25uZWN0aW9uLlxuICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9ycy5SZWd1bGFyTmF0aXZlRXJyb3IoKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBPdXRsaW5lU2VydmVyLnByb3RvdHlwZS5jaGVja1J1bm5pbmcgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiB0aGlzLmNvbm5lY3Rpb24uaXNSdW5uaW5nKCk7XG4gICAgfTtcbiAgICBPdXRsaW5lU2VydmVyLnByb3RvdHlwZS5jaGVja1JlYWNoYWJsZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY29ubmVjdGlvbi5pc1JlYWNoYWJsZSgpO1xuICAgIH07XG4gICAgcmV0dXJuIE91dGxpbmVTZXJ2ZXI7XG59KCkpO1xuZXhwb3J0cy5PdXRsaW5lU2VydmVyID0gT3V0bGluZVNlcnZlcjtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG52YXIgX192YWx1ZXMgPSAodGhpcyAmJiB0aGlzLl9fdmFsdWVzKSB8fCBmdW5jdGlvbiAobykge1xuICAgIHZhciBtID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIG9bU3ltYm9sLml0ZXJhdG9yXSwgaSA9IDA7XG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XG4gICAgcmV0dXJuIHtcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgaWYgKG8gJiYgaSA+PSBvLmxlbmd0aCkgbyA9IHZvaWQgMDtcbiAgICAgICAgICAgIHJldHVybiB7IHZhbHVlOiBvICYmIG9baSsrXSwgZG9uZTogIW8gfTtcbiAgICAgICAgfVxuICAgIH07XG59O1xuT2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFwiX19lc01vZHVsZVwiLCB7IHZhbHVlOiB0cnVlIH0pO1xudmFyIHV1aWRfMSA9IHJlcXVpcmUoXCJ1dWlkXCIpO1xudmFyIGVycm9yc18xID0gcmVxdWlyZShcIi4uL21vZGVsL2Vycm9yc1wiKTtcbnZhciBldmVudHMgPSByZXF1aXJlKFwiLi4vbW9kZWwvZXZlbnRzXCIpO1xuLy8gTWFpbnRhaW5zIGEgcGVyc2lzdGVkIHNldCBvZiBzZXJ2ZXJzIGFuZCBsaWFpc2VzIHdpdGggdGhlIGNvcmUuXG52YXIgUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkoY3JlYXRlU2VydmVyLCBldmVudFF1ZXVlLCBzdG9yYWdlKSB7XG4gICAgICAgIHRoaXMuY3JlYXRlU2VydmVyID0gY3JlYXRlU2VydmVyO1xuICAgICAgICB0aGlzLmV2ZW50UXVldWUgPSBldmVudFF1ZXVlO1xuICAgICAgICB0aGlzLnN0b3JhZ2UgPSBzdG9yYWdlO1xuICAgICAgICB0aGlzLmxhc3RGb3Jnb3R0ZW5TZXJ2ZXIgPSBudWxsO1xuICAgICAgICB0aGlzLmxvYWRTZXJ2ZXJzKCk7XG4gICAgfVxuICAgIFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5LnByb3RvdHlwZS5nZXRBbGwgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBBcnJheS5mcm9tKHRoaXMuc2VydmVyQnlJZC52YWx1ZXMoKSk7XG4gICAgfTtcbiAgICBQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeS5wcm90b3R5cGUuZ2V0QnlJZCA9IGZ1bmN0aW9uIChzZXJ2ZXJJZCkge1xuICAgICAgICByZXR1cm4gdGhpcy5zZXJ2ZXJCeUlkLmdldChzZXJ2ZXJJZCk7XG4gICAgfTtcbiAgICBQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeS5wcm90b3R5cGUuYWRkID0gZnVuY3Rpb24gKHNlcnZlckNvbmZpZykge1xuICAgICAgICB2YXIgYWxyZWFkeUFkZGVkU2VydmVyID0gdGhpcy5zZXJ2ZXJGcm9tQ29uZmlnKHNlcnZlckNvbmZpZyk7XG4gICAgICAgIGlmIChhbHJlYWR5QWRkZWRTZXJ2ZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcnNfMS5TZXJ2ZXJBbHJlYWR5QWRkZWQoYWxyZWFkeUFkZGVkU2VydmVyKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgc2VydmVyID0gdGhpcy5jcmVhdGVTZXJ2ZXIodXVpZF8xLnY0KCksIHNlcnZlckNvbmZpZywgdGhpcy5ldmVudFF1ZXVlKTtcbiAgICAgICAgdGhpcy5zZXJ2ZXJCeUlkLnNldChzZXJ2ZXIuaWQsIHNlcnZlcik7XG4gICAgICAgIHRoaXMuc3RvcmVTZXJ2ZXJzKCk7XG4gICAgICAgIHRoaXMuZXZlbnRRdWV1ZS5lbnF1ZXVlKG5ldyBldmVudHMuU2VydmVyQWRkZWQoc2VydmVyKSk7XG4gICAgfTtcbiAgICBQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeS5wcm90b3R5cGUucmVuYW1lID0gZnVuY3Rpb24gKHNlcnZlcklkLCBuZXdOYW1lKSB7XG4gICAgICAgIHZhciBzZXJ2ZXIgPSB0aGlzLnNlcnZlckJ5SWQuZ2V0KHNlcnZlcklkKTtcbiAgICAgICAgaWYgKCFzZXJ2ZXIpIHtcbiAgICAgICAgICAgIGNvbnNvbGUud2FybihcIkNhbm5vdCByZW5hbWUgbm9uZXhpc3RlbnQgc2VydmVyIFwiICsgc2VydmVySWQpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIHNlcnZlci5uYW1lID0gbmV3TmFtZTtcbiAgICAgICAgdGhpcy5zdG9yZVNlcnZlcnMoKTtcbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlLmVucXVldWUobmV3IGV2ZW50cy5TZXJ2ZXJSZW5hbWVkKHNlcnZlcikpO1xuICAgIH07XG4gICAgUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkucHJvdG90eXBlLmZvcmdldCA9IGZ1bmN0aW9uIChzZXJ2ZXJJZCkge1xuICAgICAgICB2YXIgc2VydmVyID0gdGhpcy5zZXJ2ZXJCeUlkLmdldChzZXJ2ZXJJZCk7XG4gICAgICAgIGlmICghc2VydmVyKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oXCJDYW5ub3QgcmVtb3ZlIG5vbmV4aXN0ZW50IHNlcnZlciBcIiArIHNlcnZlcklkKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnNlcnZlckJ5SWQuZGVsZXRlKHNlcnZlcklkKTtcbiAgICAgICAgdGhpcy5sYXN0Rm9yZ290dGVuU2VydmVyID0gc2VydmVyO1xuICAgICAgICB0aGlzLnN0b3JlU2VydmVycygpO1xuICAgICAgICB0aGlzLmV2ZW50UXVldWUuZW5xdWV1ZShuZXcgZXZlbnRzLlNlcnZlckZvcmdvdHRlbihzZXJ2ZXIpKTtcbiAgICB9O1xuICAgIFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5LnByb3RvdHlwZS51bmRvRm9yZ2V0ID0gZnVuY3Rpb24gKHNlcnZlcklkKSB7XG4gICAgICAgIGlmICghdGhpcy5sYXN0Rm9yZ290dGVuU2VydmVyKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oJ05vIGZvcmdvdHRlbiBzZXJ2ZXIgdG8gdW5mb3JnZXQnKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh0aGlzLmxhc3RGb3Jnb3R0ZW5TZXJ2ZXIuaWQgIT09IHNlcnZlcklkKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oJ2lkIG9mIGZvcmdvdHRlbiBzZXJ2ZXInLCB0aGlzLmxhc3RGb3Jnb3R0ZW5TZXJ2ZXIsICdkb2VzIG5vdCBtYXRjaCcsIHNlcnZlcklkKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnNlcnZlckJ5SWQuc2V0KHRoaXMubGFzdEZvcmdvdHRlblNlcnZlci5pZCwgdGhpcy5sYXN0Rm9yZ290dGVuU2VydmVyKTtcbiAgICAgICAgdGhpcy5zdG9yZVNlcnZlcnMoKTtcbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlLmVucXVldWUobmV3IGV2ZW50cy5TZXJ2ZXJGb3JnZXRVbmRvbmUodGhpcy5sYXN0Rm9yZ290dGVuU2VydmVyKSk7XG4gICAgICAgIHRoaXMubGFzdEZvcmdvdHRlblNlcnZlciA9IG51bGw7XG4gICAgfTtcbiAgICBQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeS5wcm90b3R5cGUuY29udGFpbnNTZXJ2ZXIgPSBmdW5jdGlvbiAoY29uZmlnKSB7XG4gICAgICAgIHJldHVybiAhIXRoaXMuc2VydmVyRnJvbUNvbmZpZyhjb25maWcpO1xuICAgIH07XG4gICAgUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkucHJvdG90eXBlLnNlcnZlckZyb21Db25maWcgPSBmdW5jdGlvbiAoY29uZmlnKSB7XG4gICAgICAgIHZhciBlXzEsIF9hO1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgZm9yICh2YXIgX2IgPSBfX3ZhbHVlcyh0aGlzLmdldEFsbCgpKSwgX2MgPSBfYi5uZXh0KCk7ICFfYy5kb25lOyBfYyA9IF9iLm5leHQoKSkge1xuICAgICAgICAgICAgICAgIHZhciBzZXJ2ZXIgPSBfYy52YWx1ZTtcbiAgICAgICAgICAgICAgICBpZiAoY29uZmlnc01hdGNoKHNlcnZlci5jb25maWcsIGNvbmZpZykpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHNlcnZlcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGVfMV8xKSB7IGVfMSA9IHsgZXJyb3I6IGVfMV8xIH07IH1cbiAgICAgICAgZmluYWxseSB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGlmIChfYyAmJiAhX2MuZG9uZSAmJiAoX2EgPSBfYi5yZXR1cm4pKSBfYS5jYWxsKF9iKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGZpbmFsbHkgeyBpZiAoZV8xKSB0aHJvdyBlXzEuZXJyb3I7IH1cbiAgICAgICAgfVxuICAgIH07XG4gICAgUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkucHJvdG90eXBlLnN0b3JlU2VydmVycyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIGVfMiwgX2E7XG4gICAgICAgIHZhciBjb25maWdCeUlkID0ge307XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBmb3IgKHZhciBfYiA9IF9fdmFsdWVzKHRoaXMuc2VydmVyQnlJZC52YWx1ZXMoKSksIF9jID0gX2IubmV4dCgpOyAhX2MuZG9uZTsgX2MgPSBfYi5uZXh0KCkpIHtcbiAgICAgICAgICAgICAgICB2YXIgc2VydmVyID0gX2MudmFsdWU7XG4gICAgICAgICAgICAgICAgY29uZmlnQnlJZFtzZXJ2ZXIuaWRdID0gc2VydmVyLmNvbmZpZztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZV8yXzEpIHsgZV8yID0geyBlcnJvcjogZV8yXzEgfTsgfVxuICAgICAgICBmaW5hbGx5IHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgaWYgKF9jICYmICFfYy5kb25lICYmIChfYSA9IF9iLnJldHVybikpIF9hLmNhbGwoX2IpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZmluYWxseSB7IGlmIChlXzIpIHRocm93IGVfMi5lcnJvcjsgfVxuICAgICAgICB9XG4gICAgICAgIHZhciBqc29uID0gSlNPTi5zdHJpbmdpZnkoY29uZmlnQnlJZCk7XG4gICAgICAgIHRoaXMuc3RvcmFnZS5zZXRJdGVtKFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5LlNFUlZFUlNfU1RPUkFHRV9LRVksIGpzb24pO1xuICAgIH07XG4gICAgLy8gTG9hZHMgc2VydmVycyBmcm9tIHN0b3JhZ2UsXG4gICAgLy8gcmFpc2luZyBhbiBlcnJvciBpZiB0aGVyZSBpcyBhbnkgcHJvYmxlbSBsb2FkaW5nLlxuICAgIFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5LnByb3RvdHlwZS5sb2FkU2VydmVycyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhpcy5zZXJ2ZXJCeUlkID0gbmV3IE1hcCgpO1xuICAgICAgICB2YXIgc2VydmVyc0pzb24gPSB0aGlzLnN0b3JhZ2UuZ2V0SXRlbShQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeS5TRVJWRVJTX1NUT1JBR0VfS0VZKTtcbiAgICAgICAgaWYgKCFzZXJ2ZXJzSnNvbikge1xuICAgICAgICAgICAgY29uc29sZS5kZWJ1ZyhcIm5vIHNlcnZlcnMgZm91bmQgaW4gc3RvcmFnZVwiKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB2YXIgY29uZmlnQnlJZCA9IHt9O1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgY29uZmlnQnlJZCA9IEpTT04ucGFyc2Uoc2VydmVyc0pzb24pO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJjb3VsZCBub3QgcGFyc2Ugc2F2ZWQgc2VydmVyczogXCIgKyBlLm1lc3NhZ2UpO1xuICAgICAgICB9XG4gICAgICAgIGZvciAodmFyIHNlcnZlcklkIGluIGNvbmZpZ0J5SWQpIHtcbiAgICAgICAgICAgIGlmIChjb25maWdCeUlkLmhhc093blByb3BlcnR5KHNlcnZlcklkKSkge1xuICAgICAgICAgICAgICAgIHZhciBjb25maWcgPSBjb25maWdCeUlkW3NlcnZlcklkXTtcbiAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2VydmVyID0gdGhpcy5jcmVhdGVTZXJ2ZXIoc2VydmVySWQsIGNvbmZpZywgdGhpcy5ldmVudFF1ZXVlKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXJ2ZXJCeUlkLnNldChzZXJ2ZXJJZCwgc2VydmVyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gRG9uJ3QgcHJvcGFnYXRlIHNvIG90aGVyIHN0b3JlZCBzZXJ2ZXJzIGNhbiBiZSBjcmVhdGVkLlxuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH07XG4gICAgLy8gTmFtZSBieSB3aGljaCBzZXJ2ZXJzIGFyZSBzYXZlZCB0byBzdG9yYWdlLlxuICAgIFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5LlNFUlZFUlNfU1RPUkFHRV9LRVkgPSAnc2VydmVycyc7XG4gICAgcmV0dXJuIFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5O1xufSgpKTtcbmV4cG9ydHMuUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkgPSBQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeTtcbmZ1bmN0aW9uIGNvbmZpZ3NNYXRjaChsZWZ0LCByaWdodCkge1xuICAgIHJldHVybiBsZWZ0Lmhvc3QgPT09IHJpZ2h0Lmhvc3QgJiYgbGVmdC5wb3J0ID09PSByaWdodC5wb3J0ICYmIGxlZnQubWV0aG9kID09PSByaWdodC5tZXRob2QgJiZcbiAgICAgICAgbGVmdC5wYXNzd29yZCA9PT0gcmlnaHQucGFzc3dvcmQ7XG59XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxudmFyIF9fdmFsdWVzID0gKHRoaXMgJiYgdGhpcy5fX3ZhbHVlcykgfHwgZnVuY3Rpb24gKG8pIHtcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl0sIGkgPSAwO1xuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xuICAgIHJldHVybiB7XG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGlmIChvICYmIGkgPj0gby5sZW5ndGgpIG8gPSB2b2lkIDA7XG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XG4gICAgICAgIH1cbiAgICB9O1xufTtcbnZhciBfX3JlYWQgPSAodGhpcyAmJiB0aGlzLl9fcmVhZCkgfHwgZnVuY3Rpb24gKG8sIG4pIHtcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XG4gICAgaWYgKCFtKSByZXR1cm4gbztcbiAgICB2YXIgaSA9IG0uY2FsbChvKSwgciwgYXIgPSBbXSwgZTtcbiAgICB0cnkge1xuICAgICAgICB3aGlsZSAoKG4gPT09IHZvaWQgMCB8fCBuLS0gPiAwKSAmJiAhKHIgPSBpLm5leHQoKSkuZG9uZSkgYXIucHVzaChyLnZhbHVlKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XG4gICAgZmluYWxseSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcbiAgICAgICAgfVxuICAgICAgICBmaW5hbGx5IHsgaWYgKGUpIHRocm93IGUuZXJyb3I7IH1cbiAgICB9XG4gICAgcmV0dXJuIGFyO1xufTtcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbi8vIFNldHRpbmcga2V5cyBzdXBwb3J0ZWQgYnkgdGhlIGBTZXR0aW5nc2AgY2xhc3MuXG52YXIgU2V0dGluZ3NLZXk7XG4oZnVuY3Rpb24gKFNldHRpbmdzS2V5KSB7XG4gICAgU2V0dGluZ3NLZXlbXCJWUE5fV0FSTklOR19ESVNNSVNTRURcIl0gPSBcInZwbi13YXJuaW5nLWRpc21pc3NlZFwiO1xuICAgIFNldHRpbmdzS2V5W1wiQVVUT19DT05ORUNUX0RJQUxPR19ESVNNSVNTRURcIl0gPSBcImF1dG8tY29ubmVjdC1kaWFsb2ctZGlzbWlzc2VkXCI7XG4gICAgU2V0dGluZ3NLZXlbXCJQUklWQUNZX0FDS1wiXSA9IFwicHJpdmFjeS1hY2tcIjtcbn0pKFNldHRpbmdzS2V5ID0gZXhwb3J0cy5TZXR0aW5nc0tleSB8fCAoZXhwb3J0cy5TZXR0aW5nc0tleSA9IHt9KSk7XG4vLyBQZXJzaXN0ZW50IHN0b3JhZ2UgZm9yIHVzZXIgc2V0dGluZ3MgdGhhdCBzdXBwb3J0cyBhIGxpbWl0ZWQgc2V0IG9mIGtleXMuXG52YXIgU2V0dGluZ3MgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gU2V0dGluZ3Moc3RvcmFnZSwgdmFsaWRLZXlzKSB7XG4gICAgICAgIGlmIChzdG9yYWdlID09PSB2b2lkIDApIHsgc3RvcmFnZSA9IHdpbmRvdy5sb2NhbFN0b3JhZ2U7IH1cbiAgICAgICAgaWYgKHZhbGlkS2V5cyA9PT0gdm9pZCAwKSB7IHZhbGlkS2V5cyA9IE9iamVjdC52YWx1ZXMoU2V0dGluZ3NLZXkpOyB9XG4gICAgICAgIHRoaXMuc3RvcmFnZSA9IHN0b3JhZ2U7XG4gICAgICAgIHRoaXMudmFsaWRLZXlzID0gdmFsaWRLZXlzO1xuICAgICAgICB0aGlzLnNldHRpbmdzID0gbmV3IE1hcCgpO1xuICAgICAgICB0aGlzLmxvYWRTZXR0aW5ncygpO1xuICAgIH1cbiAgICBTZXR0aW5ncy5wcm90b3R5cGUuZ2V0ID0gZnVuY3Rpb24gKGtleSkge1xuICAgICAgICByZXR1cm4gdGhpcy5zZXR0aW5ncy5nZXQoa2V5KTtcbiAgICB9O1xuICAgIFNldHRpbmdzLnByb3RvdHlwZS5zZXQgPSBmdW5jdGlvbiAoa2V5LCB2YWx1ZSkge1xuICAgICAgICBpZiAoIXRoaXMuaXNWYWxpZFNldHRpbmcoa2V5KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQ2Fubm90IHNldCBpbnZhbGlkIGtleSBcIiArIGtleSk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5zZXR0aW5ncy5zZXQoa2V5LCB2YWx1ZSk7XG4gICAgICAgIHRoaXMuc3RvcmVTZXR0aW5ncygpO1xuICAgIH07XG4gICAgU2V0dGluZ3MucHJvdG90eXBlLnJlbW92ZSA9IGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgdGhpcy5zZXR0aW5ncy5kZWxldGUoa2V5KTtcbiAgICAgICAgdGhpcy5zdG9yZVNldHRpbmdzKCk7XG4gICAgfTtcbiAgICBTZXR0aW5ncy5wcm90b3R5cGUuaXNWYWxpZFNldHRpbmcgPSBmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIHJldHVybiB0aGlzLnZhbGlkS2V5cy5pbmNsdWRlcyhrZXkpO1xuICAgIH07XG4gICAgU2V0dGluZ3MucHJvdG90eXBlLmxvYWRTZXR0aW5ncyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIHNldHRpbmdzSnNvbiA9IHRoaXMuc3RvcmFnZS5nZXRJdGVtKFNldHRpbmdzLlNUT1JBR0VfS0VZKTtcbiAgICAgICAgaWYgKCFzZXR0aW5nc0pzb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZGVidWcoXCJObyBzZXR0aW5ncyBmb3VuZCBpbiBzdG9yYWdlXCIpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIHZhciBzdG9yYWdlU2V0dGluZ3MgPSBKU09OLnBhcnNlKHNldHRpbmdzSnNvbik7XG4gICAgICAgIGZvciAodmFyIGtleSBpbiBzdG9yYWdlU2V0dGluZ3MpIHtcbiAgICAgICAgICAgIGlmIChzdG9yYWdlU2V0dGluZ3MuaGFzT3duUHJvcGVydHkoa2V5KSkge1xuICAgICAgICAgICAgICAgIHRoaXMuc2V0dGluZ3Muc2V0KGtleSwgc3RvcmFnZVNldHRpbmdzW2tleV0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfTtcbiAgICBTZXR0aW5ncy5wcm90b3R5cGUuc3RvcmVTZXR0aW5ncyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIGVfMSwgX2E7XG4gICAgICAgIHZhciBzdG9yYWdlU2V0dGluZ3MgPSB7fTtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGZvciAodmFyIF9iID0gX192YWx1ZXModGhpcy5zZXR0aW5ncyksIF9jID0gX2IubmV4dCgpOyAhX2MuZG9uZTsgX2MgPSBfYi5uZXh0KCkpIHtcbiAgICAgICAgICAgICAgICB2YXIgX2QgPSBfX3JlYWQoX2MudmFsdWUsIDIpLCBrZXkgPSBfZFswXSwgdmFsdWUgPSBfZFsxXTtcbiAgICAgICAgICAgICAgICBzdG9yYWdlU2V0dGluZ3Nba2V5XSA9IHZhbHVlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlXzFfMSkgeyBlXzEgPSB7IGVycm9yOiBlXzFfMSB9OyB9XG4gICAgICAgIGZpbmFsbHkge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBpZiAoX2MgJiYgIV9jLmRvbmUgJiYgKF9hID0gX2IucmV0dXJuKSkgX2EuY2FsbChfYik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBmaW5hbGx5IHsgaWYgKGVfMSkgdGhyb3cgZV8xLmVycm9yOyB9XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHN0b3JhZ2VTZXR0aW5nc0pzb24gPSBKU09OLnN0cmluZ2lmeShzdG9yYWdlU2V0dGluZ3MpO1xuICAgICAgICB0aGlzLnN0b3JhZ2Uuc2V0SXRlbShTZXR0aW5ncy5TVE9SQUdFX0tFWSwgc3RvcmFnZVNldHRpbmdzSnNvbik7XG4gICAgfTtcbiAgICBTZXR0aW5ncy5TVE9SQUdFX0tFWSA9ICdzZXR0aW5ncyc7XG4gICAgcmV0dXJuIFNldHRpbmdzO1xufSgpKTtcbmV4cG9ydHMuU2V0dGluZ3MgPSBTZXR0aW5ncztcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG52YXIgQWJzdHJhY3RVcGRhdGVyID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIEFic3RyYWN0VXBkYXRlcigpIHtcbiAgICAgICAgdGhpcy5saXN0ZW5lciA9IG51bGw7XG4gICAgfVxuICAgIEFic3RyYWN0VXBkYXRlci5wcm90b3R5cGUuc2V0TGlzdGVuZXIgPSBmdW5jdGlvbiAobGlzdGVuZXIpIHtcbiAgICAgICAgdGhpcy5saXN0ZW5lciA9IGxpc3RlbmVyO1xuICAgIH07XG4gICAgQWJzdHJhY3RVcGRhdGVyLnByb3RvdHlwZS5lbWl0RXZlbnQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmICh0aGlzLmxpc3RlbmVyKSB7XG4gICAgICAgICAgICB0aGlzLmxpc3RlbmVyKCk7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIHJldHVybiBBYnN0cmFjdFVwZGF0ZXI7XG59KCkpO1xuZXhwb3J0cy5BYnN0cmFjdFVwZGF0ZXIgPSBBYnN0cmFjdFVwZGF0ZXI7XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxudmFyIF9fZXh0ZW5kcyA9ICh0aGlzICYmIHRoaXMuX19leHRlbmRzKSB8fCAoZnVuY3Rpb24gKCkge1xuICAgIHZhciBleHRlbmRTdGF0aWNzID0gZnVuY3Rpb24gKGQsIGIpIHtcbiAgICAgICAgZXh0ZW5kU3RhdGljcyA9IE9iamVjdC5zZXRQcm90b3R5cGVPZiB8fFxuICAgICAgICAgICAgKHsgX19wcm90b19fOiBbXSB9IGluc3RhbmNlb2YgQXJyYXkgJiYgZnVuY3Rpb24gKGQsIGIpIHsgZC5fX3Byb3RvX18gPSBiOyB9KSB8fFxuICAgICAgICAgICAgZnVuY3Rpb24gKGQsIGIpIHsgZm9yICh2YXIgcCBpbiBiKSBpZiAoYi5oYXNPd25Qcm9wZXJ0eShwKSkgZFtwXSA9IGJbcF07IH07XG4gICAgICAgIHJldHVybiBleHRlbmRTdGF0aWNzKGQsIGIpO1xuICAgIH1cbiAgICByZXR1cm4gZnVuY3Rpb24gKGQsIGIpIHtcbiAgICAgICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcbiAgICAgICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XG4gICAgICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcbiAgICB9O1xufSkoKTtcbnZhciBfX3ZhbHVlcyA9ICh0aGlzICYmIHRoaXMuX192YWx1ZXMpIHx8IGZ1bmN0aW9uIChvKSB7XG4gICAgdmFyIG0gPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgb1tTeW1ib2wuaXRlcmF0b3JdLCBpID0gMDtcbiAgICBpZiAobSkgcmV0dXJuIG0uY2FsbChvKTtcbiAgICByZXR1cm4ge1xuICAgICAgICBuZXh0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xuICAgICAgICAgICAgcmV0dXJuIHsgdmFsdWU6IG8gJiYgb1tpKytdLCBkb25lOiAhbyB9O1xuICAgICAgICB9XG4gICAgfTtcbn07XG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG4vLy8gPHJlZmVyZW5jZSBwYXRoPScuLi8uLi90eXBlcy9hbWJpZW50L3dlYmludGVudHMuZC50cycvPlxudmFyIFVybEludGVyY2VwdG9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIFVybEludGVyY2VwdG9yKCkge1xuICAgICAgICB0aGlzLmxpc3RlbmVycyA9IFtdO1xuICAgIH1cbiAgICBVcmxJbnRlcmNlcHRvci5wcm90b3R5cGUucmVnaXN0ZXJMaXN0ZW5lciA9IGZ1bmN0aW9uIChsaXN0ZW5lcikge1xuICAgICAgICB0aGlzLmxpc3RlbmVycy5wdXNoKGxpc3RlbmVyKTtcbiAgICAgICAgaWYgKHRoaXMubGF1bmNoVXJsKSB7XG4gICAgICAgICAgICBsaXN0ZW5lcih0aGlzLmxhdW5jaFVybCk7XG4gICAgICAgICAgICB0aGlzLmxhdW5jaFVybCA9IHVuZGVmaW5lZDtcbiAgICAgICAgfVxuICAgIH07XG4gICAgVXJsSW50ZXJjZXB0b3IucHJvdG90eXBlLmV4ZWN1dGVMaXN0ZW5lcnMgPSBmdW5jdGlvbiAodXJsKSB7XG4gICAgICAgIHZhciBlXzEsIF9hO1xuICAgICAgICBpZiAoIXVybCkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdGhpcy5saXN0ZW5lcnMubGVuZ3RoKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygnbm8gbGlzdGVuZXJzIGhhdmUgYmVlbiBhZGRlZCwgZGVsYXlpbmcgaW50ZW50IGZpcmluZycpO1xuICAgICAgICAgICAgdGhpcy5sYXVuY2hVcmwgPSB1cmw7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGZvciAodmFyIF9iID0gX192YWx1ZXModGhpcy5saXN0ZW5lcnMpLCBfYyA9IF9iLm5leHQoKTsgIV9jLmRvbmU7IF9jID0gX2IubmV4dCgpKSB7XG4gICAgICAgICAgICAgICAgdmFyIGxpc3RlbmVyID0gX2MudmFsdWU7XG4gICAgICAgICAgICAgICAgbGlzdGVuZXIodXJsKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZV8xXzEpIHsgZV8xID0geyBlcnJvcjogZV8xXzEgfTsgfVxuICAgICAgICBmaW5hbGx5IHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgaWYgKF9jICYmICFfYy5kb25lICYmIChfYSA9IF9iLnJldHVybikpIF9hLmNhbGwoX2IpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZmluYWxseSB7IGlmIChlXzEpIHRocm93IGVfMS5lcnJvcjsgfVxuICAgICAgICB9XG4gICAgfTtcbiAgICByZXR1cm4gVXJsSW50ZXJjZXB0b3I7XG59KCkpO1xuZXhwb3J0cy5VcmxJbnRlcmNlcHRvciA9IFVybEludGVyY2VwdG9yO1xudmFyIEFuZHJvaWRVcmxJbnRlcmNlcHRvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoQW5kcm9pZFVybEludGVyY2VwdG9yLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIEFuZHJvaWRVcmxJbnRlcmNlcHRvcigpIHtcbiAgICAgICAgdmFyIF90aGlzID0gX3N1cGVyLmNhbGwodGhpcykgfHwgdGhpcztcbiAgICAgICAgd2luZG93LndlYmludGVudC5nZXRVcmkoZnVuY3Rpb24gKGxhdW5jaFVybCkge1xuICAgICAgICAgICAgd2luZG93LndlYmludGVudC5vbk5ld0ludGVudChfdGhpcy5leGVjdXRlTGlzdGVuZXJzLmJpbmQoX3RoaXMpKTtcbiAgICAgICAgICAgIF90aGlzLmV4ZWN1dGVMaXN0ZW5lcnMobGF1bmNoVXJsKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiBfdGhpcztcbiAgICB9XG4gICAgcmV0dXJuIEFuZHJvaWRVcmxJbnRlcmNlcHRvcjtcbn0oVXJsSW50ZXJjZXB0b3IpKTtcbmV4cG9ydHMuQW5kcm9pZFVybEludGVyY2VwdG9yID0gQW5kcm9pZFVybEludGVyY2VwdG9yO1xudmFyIEFwcGxlVXJsSW50ZXJjZXB0b3IgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKEFwcGxlVXJsSW50ZXJjZXB0b3IsIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gQXBwbGVVcmxJbnRlcmNlcHRvcihsYXVuY2hVcmwpIHtcbiAgICAgICAgdmFyIF90aGlzID0gX3N1cGVyLmNhbGwodGhpcykgfHwgdGhpcztcbiAgICAgICAgLy8gY29yZG92YS1baW9zfG9zeF0gY2FsbCBhIGdsb2JhbCBmdW5jdGlvbiB3aXRoIHRoaXMgc2lnbmF0dXJlIHdoZW4gYSBVUkwgaXMgaW50ZXJjZXB0ZWQuXG4gICAgICAgIC8vIFdlIGRlZmluZSBpdCBpbiB8Y29yZG92YV9tYWlufCwgcmVkZWZpbmUgaXQgdG8gdXNlIHRoaXMgaW50ZXJjZXB0b3IuXG4gICAgICAgIHdpbmRvdy5oYW5kbGVPcGVuVVJMID0gZnVuY3Rpb24gKHVybCkge1xuICAgICAgICAgICAgX3RoaXMuZXhlY3V0ZUxpc3RlbmVycyh1cmwpO1xuICAgICAgICB9O1xuICAgICAgICBpZiAobGF1bmNoVXJsKSB7XG4gICAgICAgICAgICBfdGhpcy5leGVjdXRlTGlzdGVuZXJzKGxhdW5jaFVybCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgIH1cbiAgICByZXR1cm4gQXBwbGVVcmxJbnRlcmNlcHRvcjtcbn0oVXJsSW50ZXJjZXB0b3IpKTtcbmV4cG9ydHMuQXBwbGVVcmxJbnRlcmNlcHRvciA9IEFwcGxlVXJsSW50ZXJjZXB0b3I7XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxudmFyIF9fZXh0ZW5kcyA9ICh0aGlzICYmIHRoaXMuX19leHRlbmRzKSB8fCAoZnVuY3Rpb24gKCkge1xuICAgIHZhciBleHRlbmRTdGF0aWNzID0gZnVuY3Rpb24gKGQsIGIpIHtcbiAgICAgICAgZXh0ZW5kU3RhdGljcyA9IE9iamVjdC5zZXRQcm90b3R5cGVPZiB8fFxuICAgICAgICAgICAgKHsgX19wcm90b19fOiBbXSB9IGluc3RhbmNlb2YgQXJyYXkgJiYgZnVuY3Rpb24gKGQsIGIpIHsgZC5fX3Byb3RvX18gPSBiOyB9KSB8fFxuICAgICAgICAgICAgZnVuY3Rpb24gKGQsIGIpIHsgZm9yICh2YXIgcCBpbiBiKSBpZiAoYi5oYXNPd25Qcm9wZXJ0eShwKSkgZFtwXSA9IGJbcF07IH07XG4gICAgICAgIHJldHVybiBleHRlbmRTdGF0aWNzKGQsIGIpO1xuICAgIH1cbiAgICByZXR1cm4gZnVuY3Rpb24gKGQsIGIpIHtcbiAgICAgICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcbiAgICAgICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XG4gICAgICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcbiAgICB9O1xufSkoKTtcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbnZhciBPdXRsaW5lRXJyb3IgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKE91dGxpbmVFcnJvciwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBPdXRsaW5lRXJyb3IobWVzc2FnZSkge1xuICAgICAgICB2YXIgX25ld1RhcmdldCA9IHRoaXMuY29uc3RydWN0b3I7XG4gICAgICAgIHZhciBfdGhpcyA9IFxuICAgICAgICAvLyByZWY6XG4gICAgICAgIC8vIGh0dHBzOi8vd3d3LnR5cGVzY3JpcHRsYW5nLm9yZy9kb2NzL2hhbmRib29rL3JlbGVhc2Utbm90ZXMvdHlwZXNjcmlwdC0yLTIuaHRtbCNzdXBwb3J0LWZvci1uZXd0YXJnZXRcbiAgICAgICAgX3N1cGVyLmNhbGwodGhpcywgbWVzc2FnZSkgfHwgdGhpcztcbiAgICAgICAgT2JqZWN0LnNldFByb3RvdHlwZU9mKF90aGlzLCBfbmV3VGFyZ2V0LnByb3RvdHlwZSk7IC8vIHJlc3RvcmUgcHJvdG90eXBlIGNoYWluXG4gICAgICAgIF90aGlzLm5hbWUgPSBfbmV3VGFyZ2V0Lm5hbWU7XG4gICAgICAgIHJldHVybiBfdGhpcztcbiAgICB9XG4gICAgcmV0dXJuIE91dGxpbmVFcnJvcjtcbn0oRXJyb3IpKTtcbmV4cG9ydHMuT3V0bGluZUVycm9yID0gT3V0bGluZUVycm9yO1xudmFyIFNlcnZlckFscmVhZHlBZGRlZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoU2VydmVyQWxyZWFkeUFkZGVkLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIFNlcnZlckFscmVhZHlBZGRlZChzZXJ2ZXIpIHtcbiAgICAgICAgdmFyIF90aGlzID0gX3N1cGVyLmNhbGwodGhpcykgfHwgdGhpcztcbiAgICAgICAgX3RoaXMuc2VydmVyID0gc2VydmVyO1xuICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgfVxuICAgIHJldHVybiBTZXJ2ZXJBbHJlYWR5QWRkZWQ7XG59KE91dGxpbmVFcnJvcikpO1xuZXhwb3J0cy5TZXJ2ZXJBbHJlYWR5QWRkZWQgPSBTZXJ2ZXJBbHJlYWR5QWRkZWQ7XG52YXIgU2VydmVySW5jb21wYXRpYmxlID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhTZXJ2ZXJJbmNvbXBhdGlibGUsIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gU2VydmVySW5jb21wYXRpYmxlKG1lc3NhZ2UpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlci5jYWxsKHRoaXMsIG1lc3NhZ2UpIHx8IHRoaXM7XG4gICAgfVxuICAgIHJldHVybiBTZXJ2ZXJJbmNvbXBhdGlibGU7XG59KE91dGxpbmVFcnJvcikpO1xuZXhwb3J0cy5TZXJ2ZXJJbmNvbXBhdGlibGUgPSBTZXJ2ZXJJbmNvbXBhdGlibGU7XG52YXIgU2VydmVyVXJsSW52YWxpZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoU2VydmVyVXJsSW52YWxpZCwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJVcmxJbnZhbGlkKG1lc3NhZ2UpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlci5jYWxsKHRoaXMsIG1lc3NhZ2UpIHx8IHRoaXM7XG4gICAgfVxuICAgIHJldHVybiBTZXJ2ZXJVcmxJbnZhbGlkO1xufShPdXRsaW5lRXJyb3IpKTtcbmV4cG9ydHMuU2VydmVyVXJsSW52YWxpZCA9IFNlcnZlclVybEludmFsaWQ7XG52YXIgT3BlcmF0aW9uVGltZWRPdXQgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKE9wZXJhdGlvblRpbWVkT3V0LCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIE9wZXJhdGlvblRpbWVkT3V0KHRpbWVvdXRNcywgb3BlcmF0aW9uTmFtZSkge1xuICAgICAgICB2YXIgX3RoaXMgPSBfc3VwZXIuY2FsbCh0aGlzKSB8fCB0aGlzO1xuICAgICAgICBfdGhpcy50aW1lb3V0TXMgPSB0aW1lb3V0TXM7XG4gICAgICAgIF90aGlzLm9wZXJhdGlvbk5hbWUgPSBvcGVyYXRpb25OYW1lO1xuICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgfVxuICAgIHJldHVybiBPcGVyYXRpb25UaW1lZE91dDtcbn0oT3V0bGluZUVycm9yKSk7XG5leHBvcnRzLk9wZXJhdGlvblRpbWVkT3V0ID0gT3BlcmF0aW9uVGltZWRPdXQ7XG52YXIgRmVlZGJhY2tTdWJtaXNzaW9uRXJyb3IgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKEZlZWRiYWNrU3VibWlzc2lvbkVycm9yLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIEZlZWRiYWNrU3VibWlzc2lvbkVycm9yKCkge1xuICAgICAgICByZXR1cm4gX3N1cGVyLmNhbGwodGhpcykgfHwgdGhpcztcbiAgICB9XG4gICAgcmV0dXJuIEZlZWRiYWNrU3VibWlzc2lvbkVycm9yO1xufShPdXRsaW5lRXJyb3IpKTtcbmV4cG9ydHMuRmVlZGJhY2tTdWJtaXNzaW9uRXJyb3IgPSBGZWVkYmFja1N1Ym1pc3Npb25FcnJvcjtcbi8vIEVycm9yIHRocm93biBieSBcIm5hdGl2ZVwiIGNvZGUuXG4vL1xuLy8gTXVzdCBiZSBrZXB0IGluIHN5bmMgd2l0aCBpdHMgQ29yZG92YSBkb3BwZWxnYW5nZXI6XG4vLyAgIGNvcmRvdmEtcGx1Z2luLW91dGxpbmUvb3V0bGluZVBsdWdpbi5qc1xuLy9cbi8vIFRPRE86IFJlbmFtZSB0aGlzIGNsYXNzLCBcInBsdWdpblwiIGlzIGEgcG9vciBuYW1lIHNpbmNlIHRoZSBFbGVjdHJvbiBhcHBzIGRvIG5vdCBoYXZlIHBsdWdpbnMuXG52YXIgT3V0bGluZVBsdWdpbkVycm9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhPdXRsaW5lUGx1Z2luRXJyb3IsIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gT3V0bGluZVBsdWdpbkVycm9yKGVycm9yQ29kZSkge1xuICAgICAgICB2YXIgX3RoaXMgPSBfc3VwZXIuY2FsbCh0aGlzKSB8fCB0aGlzO1xuICAgICAgICBfdGhpcy5lcnJvckNvZGUgPSBlcnJvckNvZGU7XG4gICAgICAgIHJldHVybiBfdGhpcztcbiAgICB9XG4gICAgcmV0dXJuIE91dGxpbmVQbHVnaW5FcnJvcjtcbn0oT3V0bGluZUVycm9yKSk7XG5leHBvcnRzLk91dGxpbmVQbHVnaW5FcnJvciA9IE91dGxpbmVQbHVnaW5FcnJvcjtcbi8vIE1hcmtlciBjbGFzcyBmb3IgZXJyb3JzIG9yaWdpbmF0aW5nIGluIG5hdGl2ZSBjb2RlLlxuLy8gQmlmdXJjYXRlcyBpbnRvIHR3byBzdWJjbGFzc2VzOlxuLy8gIC0gXCJleHBlY3RlZFwiIGVycm9ycyBvcmlnaW5hdGluZyBpbiBuYXRpdmUgY29kZSwgZS5nLiBpbmNvcnJlY3QgcGFzc3dvcmRcbi8vICAtIFwidW5leHBlY3RlZFwiIGVycm9ycyBvcmlnaW5hdGluZyBpbiBuYXRpdmUgY29kZSwgZS5nLiB1bmhhbmRsZWQgcm91dGluZyB0YWJsZVxudmFyIE5hdGl2ZUVycm9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhOYXRpdmVFcnJvciwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBOYXRpdmVFcnJvcigpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gTmF0aXZlRXJyb3I7XG59KE91dGxpbmVFcnJvcikpO1xuZXhwb3J0cy5OYXRpdmVFcnJvciA9IE5hdGl2ZUVycm9yO1xudmFyIFJlZ3VsYXJOYXRpdmVFcnJvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoUmVndWxhck5hdGl2ZUVycm9yLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIFJlZ3VsYXJOYXRpdmVFcnJvcigpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gUmVndWxhck5hdGl2ZUVycm9yO1xufShOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5SZWd1bGFyTmF0aXZlRXJyb3IgPSBSZWd1bGFyTmF0aXZlRXJyb3I7XG52YXIgUmVkRmxhZ05hdGl2ZUVycm9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhSZWRGbGFnTmF0aXZlRXJyb3IsIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gUmVkRmxhZ05hdGl2ZUVycm9yKCkge1xuICAgICAgICByZXR1cm4gX3N1cGVyICE9PSBudWxsICYmIF9zdXBlci5hcHBseSh0aGlzLCBhcmd1bWVudHMpIHx8IHRoaXM7XG4gICAgfVxuICAgIHJldHVybiBSZWRGbGFnTmF0aXZlRXJyb3I7XG59KE5hdGl2ZUVycm9yKSk7XG5leHBvcnRzLlJlZEZsYWdOYXRpdmVFcnJvciA9IFJlZEZsYWdOYXRpdmVFcnJvcjtcbi8vLy8vL1xuLy8gXCJFeHBlY3RlZFwiIGVycm9ycy5cbi8vLy8vL1xudmFyIFVuZXhwZWN0ZWRQbHVnaW5FcnJvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoVW5leHBlY3RlZFBsdWdpbkVycm9yLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIFVuZXhwZWN0ZWRQbHVnaW5FcnJvcigpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gVW5leHBlY3RlZFBsdWdpbkVycm9yO1xufShSZWd1bGFyTmF0aXZlRXJyb3IpKTtcbmV4cG9ydHMuVW5leHBlY3RlZFBsdWdpbkVycm9yID0gVW5leHBlY3RlZFBsdWdpbkVycm9yO1xudmFyIFZwblBlcm1pc3Npb25Ob3RHcmFudGVkID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhWcG5QZXJtaXNzaW9uTm90R3JhbnRlZCwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBWcG5QZXJtaXNzaW9uTm90R3JhbnRlZCgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gVnBuUGVybWlzc2lvbk5vdEdyYW50ZWQ7XG59KFJlZ3VsYXJOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5WcG5QZXJtaXNzaW9uTm90R3JhbnRlZCA9IFZwblBlcm1pc3Npb25Ob3RHcmFudGVkO1xudmFyIEludmFsaWRTZXJ2ZXJDcmVkZW50aWFscyA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoSW52YWxpZFNlcnZlckNyZWRlbnRpYWxzLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIEludmFsaWRTZXJ2ZXJDcmVkZW50aWFscygpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gSW52YWxpZFNlcnZlckNyZWRlbnRpYWxzO1xufShSZWd1bGFyTmF0aXZlRXJyb3IpKTtcbmV4cG9ydHMuSW52YWxpZFNlcnZlckNyZWRlbnRpYWxzID0gSW52YWxpZFNlcnZlckNyZWRlbnRpYWxzO1xudmFyIFJlbW90ZVVkcEZvcndhcmRpbmdEaXNhYmxlZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIFJlbW90ZVVkcEZvcndhcmRpbmdEaXNhYmxlZCgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkO1xufShSZWd1bGFyTmF0aXZlRXJyb3IpKTtcbmV4cG9ydHMuUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkID0gUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkO1xudmFyIFNlcnZlclVucmVhY2hhYmxlID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhTZXJ2ZXJVbnJlYWNoYWJsZSwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJVbnJlYWNoYWJsZSgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gU2VydmVyVW5yZWFjaGFibGU7XG59KFJlZ3VsYXJOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5TZXJ2ZXJVbnJlYWNoYWJsZSA9IFNlcnZlclVucmVhY2hhYmxlO1xudmFyIElsbGVnYWxTZXJ2ZXJDb25maWd1cmF0aW9uID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhJbGxlZ2FsU2VydmVyQ29uZmlndXJhdGlvbiwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBJbGxlZ2FsU2VydmVyQ29uZmlndXJhdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gSWxsZWdhbFNlcnZlckNvbmZpZ3VyYXRpb247XG59KFJlZ3VsYXJOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5JbGxlZ2FsU2VydmVyQ29uZmlndXJhdGlvbiA9IElsbGVnYWxTZXJ2ZXJDb25maWd1cmF0aW9uO1xudmFyIE5vQWRtaW5QZXJtaXNzaW9ucyA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoTm9BZG1pblBlcm1pc3Npb25zLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIE5vQWRtaW5QZXJtaXNzaW9ucygpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gTm9BZG1pblBlcm1pc3Npb25zO1xufShSZWd1bGFyTmF0aXZlRXJyb3IpKTtcbmV4cG9ydHMuTm9BZG1pblBlcm1pc3Npb25zID0gTm9BZG1pblBlcm1pc3Npb25zO1xudmFyIFN5c3RlbUNvbmZpZ3VyYXRpb25FeGNlcHRpb24gPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKFN5c3RlbUNvbmZpZ3VyYXRpb25FeGNlcHRpb24sIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gU3lzdGVtQ29uZmlndXJhdGlvbkV4Y2VwdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gU3lzdGVtQ29uZmlndXJhdGlvbkV4Y2VwdGlvbjtcbn0oUmVndWxhck5hdGl2ZUVycm9yKSk7XG5leHBvcnRzLlN5c3RlbUNvbmZpZ3VyYXRpb25FeGNlcHRpb24gPSBTeXN0ZW1Db25maWd1cmF0aW9uRXhjZXB0aW9uO1xuLy8vLy8vXG4vLyBOb3csIFwidW5leHBlY3RlZFwiIGVycm9ycy5cbi8vIFVzZSB0aGVzZSBzcGFyaW5nbHkgYmVjYXVzZSBlYWNoIG9jY3VycmVuY2UgdHJpZ2dlcnMgYSBTZW50cnkgcmVwb3J0LlxuLy8vLy8vXG4vLyBXaW5kb3dzLlxudmFyIFNoYWRvd3NvY2tzU3RhcnRGYWlsdXJlID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhTaGFkb3dzb2Nrc1N0YXJ0RmFpbHVyZSwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBTaGFkb3dzb2Nrc1N0YXJ0RmFpbHVyZSgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gU2hhZG93c29ja3NTdGFydEZhaWx1cmU7XG59KFJlZEZsYWdOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5TaGFkb3dzb2Nrc1N0YXJ0RmFpbHVyZSA9IFNoYWRvd3NvY2tzU3RhcnRGYWlsdXJlO1xudmFyIENvbmZpZ3VyZVN5c3RlbVByb3h5RmFpbHVyZSA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIENvbmZpZ3VyZVN5c3RlbVByb3h5RmFpbHVyZSgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlO1xufShSZWRGbGFnTmF0aXZlRXJyb3IpKTtcbmV4cG9ydHMuQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlID0gQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlO1xudmFyIFVuc3VwcG9ydGVkUm91dGluZ1RhYmxlID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhVbnN1cHBvcnRlZFJvdXRpbmdUYWJsZSwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBVbnN1cHBvcnRlZFJvdXRpbmdUYWJsZSgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gVW5zdXBwb3J0ZWRSb3V0aW5nVGFibGU7XG59KFJlZEZsYWdOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5VbnN1cHBvcnRlZFJvdXRpbmdUYWJsZSA9IFVuc3VwcG9ydGVkUm91dGluZ1RhYmxlO1xuLy8gVXNlZCBvbiBBbmRyb2lkIGFuZCBBcHBsZSB0byBpbmRpY2F0ZSB0aGF0IHRoZSBwbHVnaW4gZmFpbGVkIHRvIGVzdGFibGlzaCB0aGUgVlBOIHR1bm5lbC5cbnZhciBWcG5TdGFydEZhaWx1cmUgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKFZwblN0YXJ0RmFpbHVyZSwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBWcG5TdGFydEZhaWx1cmUoKSB7XG4gICAgICAgIHJldHVybiBfc3VwZXIgIT09IG51bGwgJiYgX3N1cGVyLmFwcGx5KHRoaXMsIGFyZ3VtZW50cykgfHwgdGhpcztcbiAgICB9XG4gICAgcmV0dXJuIFZwblN0YXJ0RmFpbHVyZTtcbn0oUmVkRmxhZ05hdGl2ZUVycm9yKSk7XG5leHBvcnRzLlZwblN0YXJ0RmFpbHVyZSA9IFZwblN0YXJ0RmFpbHVyZTtcbi8vIENvbnZlcnRzIGFuIEVycm9yQ29kZSAtIG9yaWdpbmF0aW5nIGluIFwibmF0aXZlXCIgY29kZSAtIHRvIGFuIGluc3RhbmNlIG9mIHRoZSByZWxldmFudFxuLy8gT3V0bGluZUVycm9yIHN1YmNsYXNzLlxuLy8gVGhyb3dzIGlmIHRoZSBlcnJvciBjb2RlIGlzIG5vdCBvbmUgZGVmaW5lZCBpbiBFcnJvckNvZGUgb3IgaXMgRXJyb3JDb2RlLk5PX0VSUk9SLlxuZnVuY3Rpb24gZnJvbUVycm9yQ29kZShlcnJvckNvZGUpIHtcbiAgICBzd2l0Y2ggKGVycm9yQ29kZSkge1xuICAgICAgICBjYXNlIDEgLyogVU5FWFBFQ1RFRCAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgVW5leHBlY3RlZFBsdWdpbkVycm9yKCk7XG4gICAgICAgIGNhc2UgMiAvKiBWUE5fUEVSTUlTU0lPTl9OT1RfR1JBTlRFRCAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgVnBuUGVybWlzc2lvbk5vdEdyYW50ZWQoKTtcbiAgICAgICAgY2FzZSAzIC8qIElOVkFMSURfU0VSVkVSX0NSRURFTlRJQUxTICovOlxuICAgICAgICAgICAgcmV0dXJuIG5ldyBJbnZhbGlkU2VydmVyQ3JlZGVudGlhbHMoKTtcbiAgICAgICAgY2FzZSA0IC8qIFVEUF9SRUxBWV9OT1RfRU5BQkxFRCAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkKCk7XG4gICAgICAgIGNhc2UgNSAvKiBTRVJWRVJfVU5SRUFDSEFCTEUgKi86XG4gICAgICAgICAgICByZXR1cm4gbmV3IFNlcnZlclVucmVhY2hhYmxlKCk7XG4gICAgICAgIGNhc2UgNiAvKiBWUE5fU1RBUlRfRkFJTFVSRSAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgVnBuU3RhcnRGYWlsdXJlKCk7XG4gICAgICAgIGNhc2UgNyAvKiBJTExFR0FMX1NFUlZFUl9DT05GSUdVUkFUSU9OICovOlxuICAgICAgICAgICAgcmV0dXJuIG5ldyBJbGxlZ2FsU2VydmVyQ29uZmlndXJhdGlvbigpO1xuICAgICAgICBjYXNlIDggLyogU0hBRE9XU09DS1NfU1RBUlRfRkFJTFVSRSAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgU2hhZG93c29ja3NTdGFydEZhaWx1cmUoKTtcbiAgICAgICAgY2FzZSA5IC8qIENPTkZJR1VSRV9TWVNURU1fUFJPWFlfRkFJTFVSRSAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlKCk7XG4gICAgICAgIGNhc2UgMTAgLyogTk9fQURNSU5fUEVSTUlTU0lPTlMgKi86XG4gICAgICAgICAgICByZXR1cm4gbmV3IE5vQWRtaW5QZXJtaXNzaW9ucygpO1xuICAgICAgICBjYXNlIDExIC8qIFVOU1VQUE9SVEVEX1JPVVRJTkdfVEFCTEUgKi86XG4gICAgICAgICAgICByZXR1cm4gbmV3IFVuc3VwcG9ydGVkUm91dGluZ1RhYmxlKCk7XG4gICAgICAgIGNhc2UgMTIgLyogU1lTVEVNX01JU0NPTkZJR1VSRUQgKi86XG4gICAgICAgICAgICByZXR1cm4gbmV3IFN5c3RlbUNvbmZpZ3VyYXRpb25FeGNlcHRpb24oKTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcInVua25vd24gRXJyb3JDb2RlIFwiICsgZXJyb3JDb2RlKTtcbiAgICB9XG59XG5leHBvcnRzLmZyb21FcnJvckNvZGUgPSBmcm9tRXJyb3JDb2RlO1xuLy8gQ29udmVydHMgYSBOYXRpdmVFcnJvciB0byBhbiBFcnJvckNvZGUuXG4vLyBUaHJvd3MgaWYgdGhlIGVycm9yIGlzIG5vdCBhIHN1YmNsYXNzIG9mIE5hdGl2ZUVycm9yLlxuZnVuY3Rpb24gdG9FcnJvckNvZGUoZSkge1xuICAgIGlmIChlIGluc3RhbmNlb2YgVW5leHBlY3RlZFBsdWdpbkVycm9yKSB7XG4gICAgICAgIHJldHVybiAxIC8qIFVORVhQRUNURUQgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBWcG5QZXJtaXNzaW9uTm90R3JhbnRlZCkge1xuICAgICAgICByZXR1cm4gMiAvKiBWUE5fUEVSTUlTU0lPTl9OT1RfR1JBTlRFRCAqLztcbiAgICB9XG4gICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEludmFsaWRTZXJ2ZXJDcmVkZW50aWFscykge1xuICAgICAgICByZXR1cm4gMyAvKiBJTlZBTElEX1NFUlZFUl9DUkVERU5USUFMUyAqLztcbiAgICB9XG4gICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIFJlbW90ZVVkcEZvcndhcmRpbmdEaXNhYmxlZCkge1xuICAgICAgICByZXR1cm4gNCAvKiBVRFBfUkVMQVlfTk9UX0VOQUJMRUQgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBTZXJ2ZXJVbnJlYWNoYWJsZSkge1xuICAgICAgICByZXR1cm4gNSAvKiBTRVJWRVJfVU5SRUFDSEFCTEUgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBWcG5TdGFydEZhaWx1cmUpIHtcbiAgICAgICAgcmV0dXJuIDYgLyogVlBOX1NUQVJUX0ZBSUxVUkUgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBJbGxlZ2FsU2VydmVyQ29uZmlndXJhdGlvbikge1xuICAgICAgICByZXR1cm4gNyAvKiBJTExFR0FMX1NFUlZFUl9DT05GSUdVUkFUSU9OICovO1xuICAgIH1cbiAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgU2hhZG93c29ja3NTdGFydEZhaWx1cmUpIHtcbiAgICAgICAgcmV0dXJuIDggLyogU0hBRE9XU09DS1NfU1RBUlRfRkFJTFVSRSAqLztcbiAgICB9XG4gICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIENvbmZpZ3VyZVN5c3RlbVByb3h5RmFpbHVyZSkge1xuICAgICAgICByZXR1cm4gOSAvKiBDT05GSUdVUkVfU1lTVEVNX1BST1hZX0ZBSUxVUkUgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBVbnN1cHBvcnRlZFJvdXRpbmdUYWJsZSkge1xuICAgICAgICByZXR1cm4gMTEgLyogVU5TVVBQT1JURURfUk9VVElOR19UQUJMRSAqLztcbiAgICB9XG4gICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIE5vQWRtaW5QZXJtaXNzaW9ucykge1xuICAgICAgICByZXR1cm4gMTAgLyogTk9fQURNSU5fUEVSTUlTU0lPTlMgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBTeXN0ZW1Db25maWd1cmF0aW9uRXhjZXB0aW9uKSB7XG4gICAgICAgIHJldHVybiAxMiAvKiBTWVNURU1fTUlTQ09ORklHVVJFRCAqLztcbiAgICB9XG4gICAgdGhyb3cgbmV3IEVycm9yKFwidW5rbm93biBOYXRpdmVFcnJvciBcIiArIGUubmFtZSk7XG59XG5leHBvcnRzLnRvRXJyb3JDb2RlID0gdG9FcnJvckNvZGU7XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxudmFyIF9fdmFsdWVzID0gKHRoaXMgJiYgdGhpcy5fX3ZhbHVlcykgfHwgZnVuY3Rpb24gKG8pIHtcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl0sIGkgPSAwO1xuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xuICAgIHJldHVybiB7XG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGlmIChvICYmIGkgPj0gby5sZW5ndGgpIG8gPSB2b2lkIDA7XG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XG4gICAgICAgIH1cbiAgICB9O1xufTtcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbnZhciBTZXJ2ZXJBZGRlZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJBZGRlZChzZXJ2ZXIpIHtcbiAgICAgICAgdGhpcy5zZXJ2ZXIgPSBzZXJ2ZXI7XG4gICAgfVxuICAgIHJldHVybiBTZXJ2ZXJBZGRlZDtcbn0oKSk7XG5leHBvcnRzLlNlcnZlckFkZGVkID0gU2VydmVyQWRkZWQ7XG52YXIgU2VydmVyQWxyZWFkeUFkZGVkID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIFNlcnZlckFscmVhZHlBZGRlZChzZXJ2ZXIpIHtcbiAgICAgICAgdGhpcy5zZXJ2ZXIgPSBzZXJ2ZXI7XG4gICAgfVxuICAgIHJldHVybiBTZXJ2ZXJBbHJlYWR5QWRkZWQ7XG59KCkpO1xuZXhwb3J0cy5TZXJ2ZXJBbHJlYWR5QWRkZWQgPSBTZXJ2ZXJBbHJlYWR5QWRkZWQ7XG52YXIgU2VydmVyRm9yZ290dGVuID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIFNlcnZlckZvcmdvdHRlbihzZXJ2ZXIpIHtcbiAgICAgICAgdGhpcy5zZXJ2ZXIgPSBzZXJ2ZXI7XG4gICAgfVxuICAgIHJldHVybiBTZXJ2ZXJGb3Jnb3R0ZW47XG59KCkpO1xuZXhwb3J0cy5TZXJ2ZXJGb3Jnb3R0ZW4gPSBTZXJ2ZXJGb3Jnb3R0ZW47XG52YXIgU2VydmVyRm9yZ2V0VW5kb25lID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIFNlcnZlckZvcmdldFVuZG9uZShzZXJ2ZXIpIHtcbiAgICAgICAgdGhpcy5zZXJ2ZXIgPSBzZXJ2ZXI7XG4gICAgfVxuICAgIHJldHVybiBTZXJ2ZXJGb3JnZXRVbmRvbmU7XG59KCkpO1xuZXhwb3J0cy5TZXJ2ZXJGb3JnZXRVbmRvbmUgPSBTZXJ2ZXJGb3JnZXRVbmRvbmU7XG52YXIgU2VydmVyUmVuYW1lZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJSZW5hbWVkKHNlcnZlcikge1xuICAgICAgICB0aGlzLnNlcnZlciA9IHNlcnZlcjtcbiAgICB9XG4gICAgcmV0dXJuIFNlcnZlclJlbmFtZWQ7XG59KCkpO1xuZXhwb3J0cy5TZXJ2ZXJSZW5hbWVkID0gU2VydmVyUmVuYW1lZDtcbnZhciBTZXJ2ZXJVcmxJbnZhbGlkID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIFNlcnZlclVybEludmFsaWQoc2VydmVyVXJsKSB7XG4gICAgICAgIHRoaXMuc2VydmVyVXJsID0gc2VydmVyVXJsO1xuICAgIH1cbiAgICByZXR1cm4gU2VydmVyVXJsSW52YWxpZDtcbn0oKSk7XG5leHBvcnRzLlNlcnZlclVybEludmFsaWQgPSBTZXJ2ZXJVcmxJbnZhbGlkO1xudmFyIFNlcnZlckNvbm5lY3RlZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJDb25uZWN0ZWQoc2VydmVyKSB7XG4gICAgICAgIHRoaXMuc2VydmVyID0gc2VydmVyO1xuICAgIH1cbiAgICByZXR1cm4gU2VydmVyQ29ubmVjdGVkO1xufSgpKTtcbmV4cG9ydHMuU2VydmVyQ29ubmVjdGVkID0gU2VydmVyQ29ubmVjdGVkO1xudmFyIFNlcnZlckRpc2Nvbm5lY3RlZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJEaXNjb25uZWN0ZWQoc2VydmVyKSB7XG4gICAgICAgIHRoaXMuc2VydmVyID0gc2VydmVyO1xuICAgIH1cbiAgICByZXR1cm4gU2VydmVyRGlzY29ubmVjdGVkO1xufSgpKTtcbmV4cG9ydHMuU2VydmVyRGlzY29ubmVjdGVkID0gU2VydmVyRGlzY29ubmVjdGVkO1xudmFyIFNlcnZlclJlY29ubmVjdGluZyA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJSZWNvbm5lY3Rpbmcoc2VydmVyKSB7XG4gICAgICAgIHRoaXMuc2VydmVyID0gc2VydmVyO1xuICAgIH1cbiAgICByZXR1cm4gU2VydmVyUmVjb25uZWN0aW5nO1xufSgpKTtcbmV4cG9ydHMuU2VydmVyUmVjb25uZWN0aW5nID0gU2VydmVyUmVjb25uZWN0aW5nO1xuLy8gU2ltcGxlIHB1Ymxpc2hlci1zdWJzY3JpYmVyIHF1ZXVlLlxudmFyIEV2ZW50UXVldWUgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gRXZlbnRRdWV1ZSgpIHtcbiAgICAgICAgdGhpcy5xdWV1ZWRFdmVudHMgPSBbXTtcbiAgICAgICAgdGhpcy5saXN0ZW5lcnNCeUV2ZW50VHlwZSA9IG5ldyBNYXAoKTtcbiAgICAgICAgdGhpcy5pc1N0YXJ0ZWQgPSBmYWxzZTtcbiAgICAgICAgdGhpcy5pc1B1Ymxpc2hpbmcgPSBmYWxzZTtcbiAgICB9XG4gICAgRXZlbnRRdWV1ZS5wcm90b3R5cGUuc3RhcnRQdWJsaXNoaW5nID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB0aGlzLmlzU3RhcnRlZCA9IHRydWU7XG4gICAgICAgIHRoaXMucHVibGlzaFF1ZXVlZEV2ZW50cygpO1xuICAgIH07XG4gICAgLy8gUmVnaXN0ZXJzIGEgbGlzdGVuZXIgZm9yIGV2ZW50cyBvZiB0aGUgdHlwZSBvZiB0aGUgZ2l2ZW4gY29uc3RydWN0b3IuXG4gICAgRXZlbnRRdWV1ZS5wcm90b3R5cGUuc3Vic2NyaWJlID0gZnVuY3Rpb24gKGV2ZW50VHlwZSwgbGlzdGVuZXIpIHtcbiAgICAgICAgdmFyIGxpc3RlbmVycyA9IHRoaXMubGlzdGVuZXJzQnlFdmVudFR5cGUuZ2V0KGV2ZW50VHlwZSk7XG4gICAgICAgIGlmICghbGlzdGVuZXJzKSB7XG4gICAgICAgICAgICBsaXN0ZW5lcnMgPSBbXTtcbiAgICAgICAgICAgIHRoaXMubGlzdGVuZXJzQnlFdmVudFR5cGUuc2V0KGV2ZW50VHlwZSwgbGlzdGVuZXJzKTtcbiAgICAgICAgfVxuICAgICAgICBsaXN0ZW5lcnMucHVzaChsaXN0ZW5lcik7XG4gICAgfTtcbiAgICAvLyBFbnF1ZXVlcyB0aGUgZ2l2ZW4gZXZlbnQgZm9yIHB1Ymxpc2hpbmcgYW5kIHB1Ymxpc2hlcyBhbGwgcXVldWVkIGV2ZW50cyBpZlxuICAgIC8vIHB1Ymxpc2hpbmcgaXMgbm90IGFscmVhZHkgaGFwcGVuaW5nLlxuICAgIC8vXG4gICAgLy8gVGhlIGVucXVldWUgbWV0aG9kIGlzIHJlZW50cmFudDogaXQgbWF5IGJlIGNhbGxlZCBieSBhbiBldmVudCBsaXN0ZW5lclxuICAgIC8vIGR1cmluZyB0aGUgcHVibGlzaGluZyBvZiB0aGUgZXZlbnRzLiBJbiB0aGF0IGNhc2UgdGhlIG1ldGhvZCBhZGRzIHRoZSBldmVudFxuICAgIC8vIHRvIHRoZSBlbmQgb2YgdGhlIHF1ZXVlIGFuZCByZXR1cm5zIGltbWVkaWF0ZWx5LlxuICAgIC8vXG4gICAgLy8gVGhpcyBndWFyYW50ZWVzIHRoYXQgZXZlbnRzIGFyZSBwdWJsaXNoZWQgYW5kIGhhbmRsZWQgaW4gdGhlIG9yZGVyIHRoYXRcbiAgICAvLyB0aGV5IGFyZSBxdWV1ZWQuXG4gICAgLy9cbiAgICAvLyBUaGVyZSdzIG5vIGd1YXJhbnRlZSB0aGF0IHRoZSBzdWJzY3JpYmVycyBmb3IgdGhlIGV2ZW50IGhhdmUgYmVlbiBjYWxsZWQgYnlcbiAgICAvLyB0aGUgdGltZSB0aGlzIGZ1bmN0aW9uIHJldHVybnMuXG4gICAgRXZlbnRRdWV1ZS5wcm90b3R5cGUuZW5xdWV1ZSA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICB0aGlzLnF1ZXVlZEV2ZW50cy5wdXNoKGV2ZW50KTtcbiAgICAgICAgaWYgKHRoaXMuaXNTdGFydGVkKSB7XG4gICAgICAgICAgICB0aGlzLnB1Ymxpc2hRdWV1ZWRFdmVudHMoKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLy8gVHJpZ2dlcnMgdGhlIHN1YnNjcmliZXJzIGZvciBhbGwgdGhlIGVucXVldWVkIGV2ZW50cy5cbiAgICBFdmVudFF1ZXVlLnByb3RvdHlwZS5wdWJsaXNoUXVldWVkRXZlbnRzID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgZV8xLCBfYTtcbiAgICAgICAgaWYgKHRoaXMuaXNQdWJsaXNoaW5nKVxuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB0aGlzLmlzUHVibGlzaGluZyA9IHRydWU7XG4gICAgICAgIHdoaWxlICh0aGlzLnF1ZXVlZEV2ZW50cy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB2YXIgZXZlbnRfMSA9IHRoaXMucXVldWVkRXZlbnRzLnNoaWZ0KCk7XG4gICAgICAgICAgICB2YXIgbGlzdGVuZXJzID0gdGhpcy5saXN0ZW5lcnNCeUV2ZW50VHlwZS5nZXQoZXZlbnRfMS5jb25zdHJ1Y3Rvcik7XG4gICAgICAgICAgICBpZiAoIWxpc3RlbmVycykge1xuICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybignRHJvcHBpbmcgZXZlbnQgd2l0aCBubyBsaXN0ZW5lcnM6JywgZXZlbnRfMSk7XG4gICAgICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGZvciAodmFyIGxpc3RlbmVyc18xID0gX192YWx1ZXMobGlzdGVuZXJzKSwgbGlzdGVuZXJzXzFfMSA9IGxpc3RlbmVyc18xLm5leHQoKTsgIWxpc3RlbmVyc18xXzEuZG9uZTsgbGlzdGVuZXJzXzFfMSA9IGxpc3RlbmVyc18xLm5leHQoKSkge1xuICAgICAgICAgICAgICAgICAgICB2YXIgbGlzdGVuZXIgPSBsaXN0ZW5lcnNfMV8xLnZhbHVlO1xuICAgICAgICAgICAgICAgICAgICBsaXN0ZW5lcihldmVudF8xKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCAoZV8xXzEpIHsgZV8xID0geyBlcnJvcjogZV8xXzEgfTsgfVxuICAgICAgICAgICAgZmluYWxseSB7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGxpc3RlbmVyc18xXzEgJiYgIWxpc3RlbmVyc18xXzEuZG9uZSAmJiAoX2EgPSBsaXN0ZW5lcnNfMS5yZXR1cm4pKSBfYS5jYWxsKGxpc3RlbmVyc18xKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZmluYWxseSB7IGlmIChlXzEpIHRocm93IGVfMS5lcnJvcjsgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHRoaXMuaXNQdWJsaXNoaW5nID0gZmFsc2U7XG4gICAgfTtcbiAgICByZXR1cm4gRXZlbnRRdWV1ZTtcbn0oKSk7XG5leHBvcnRzLkV2ZW50UXVldWUgPSBFdmVudFF1ZXVlO1xuIl19
