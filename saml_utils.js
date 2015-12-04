var zlib = Npm.require('zlib');
var xml2js = Npm.require('xml2js');
var xmlCrypto = Npm.require('xml-crypto');
var crypto = Npm.require('crypto');
var xmldom = Npm.require('xmldom');
var querystring = Npm.require('querystring');
var xmlbuilder = Npm.require('xmlbuilder');
var xmlenc = Npm.require('xml-encryption');
var xpath = xmlCrypto.xpath;
var Dom = xmldom.DOMParser;
var fs = Npm.require('node-fs');

var prefixMatch = new RegExp(/(?!xmlns)^.*:/);



SAML = function (options) {
    this.options = this.initialize(options);
};

var stripPrefix = function (str) {
    return str.replace(prefixMatch, '');
};

SAML.prototype.initialize = function (options) {
    var self = this;
    if (!options) {
        options = {};
    }

    if (!options.protocol) {
        options.protocol = 'https://';
    }

    if (!options.path) {
        options.path = '/saml/consume';
    }

    if (!options.issuer) {
        options.issuer = 'onelogin_saml';
    }

    if (options.identifierFormat === undefined) {
        options.identifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    }

    if (options.authnContext === undefined) {
        options.authnContext = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    }

    if (options.privateKeyFile) {
        self.privateKey = fs.readFileSync(options.privateKeyFile);
    }

    if (options.privateKey) {
        self.privateKey = options.privateKey;
    }
    
    if (options.privateCertFile) {
        self.privateCert = fs.readFileSync(options.privateCertFile);
    }

    if (options.privateCert) {
        self.privateCert = options.privateCert;
    }
    
    return options;
};

SAML.prototype.generateUniqueID = function () {
    var chars = "abcdef0123456789";
    var uniqueID = "";
    for (var i = 0; i < 20; i++) {
        uniqueID += chars.substr(Math.floor((Math.random() * 15)), 1);
    }
    return uniqueID;
};

SAML.prototype.generateInstant = function () {
    var date = new Date();
    return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth() + 1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + (date.getUTCHours() + 2)).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
};

SAML.prototype.signRequest = function (xml) {
    if (Meteor.settings.debug >= 2) {
        console.log("[ SAML ] Signing request");
    }

    var signer = crypto.createSign('RSA-SHA256');
    signer.update(xml);
    return signer.sign(this.privateKey, 'base64');
}


SAML.prototype.generateAuthorizeRequest = function (req) {
    var id = "_" + this.generateUniqueID();
    var instant = this.generateInstant();

    // Post-auth destination
    if (this.options.callbackUrl) {
        callbackUrl = this.options.callbackUrl;
    } else {
        var callbackUrl = this.options.protocol + req.headers.host + this.options.path;
    }

    if (this.options.id)
        id = this.options.id;

    if (this.options.assertionConsumerServiceIndex !== undefined) {
        var assertionConsumerService = 'AssertionConsumerServiceIndex="' + this.options.assertionConsumerServiceIndex + '"';
    } else {
        var assertionConsumerService = 'AssertionConsumerServiceURL="' + callbackUrl + '"';
    }

    var request =
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant +
        "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" " + assertionConsumerService + " Destination=\"" +
        this.options.entryPoint + "\">" +
        "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>\n";

    if (this.options.identifierFormat) {
        request += "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat +
            "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n";
    }

    if (this.options.authnContext) {
        request +=
            "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
            "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.authnContext + 
            "</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n"
    }

    request += "</samlp:AuthnRequest>";


    return request;
};

SAML.prototype.generateLogoutRequest = function (options) {
    // options should be of the form
    // nameId: <nameId as submitted during SAML SSO>
    // sessionIndex: sessionIndex
    // --- NO SAMLsettings: <Meteor.setting.saml  entry for the provider you want to SLO from   

    var id = "_" + this.generateUniqueID();
    var instant = this.generateInstant();

    var request = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"  " +
        "ID=\"" + id + "\" " +
        "Version=\"2.0\" " +
        "IssueInstant=\"" + instant + "\" " +
        "Destination=\"" + this.options.idpSLORedirectURL + "\" " +
        ">" +
        "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>" +
        "<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
        "NameQualifier=\"http://id.init8.net:8080/openam\" " +
        "SPNameQualifier=\"" + this.options.issuer + "\" " +
        "Format=\"" + this.options.identifierFormat + "\">" +
        options.nameID + "</saml:NameID>" +
        "<samlp:SessionIndex xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">" + options.sessionIndex + "</samlp:SessionIndex>" +
        "</samlp:LogoutRequest>";
    if (Meteor.settings.debug >= 3) {
        console.log("[ SAML ] Logout request: " + request);
    }
    return {
        request: request,
        id: id
    };
}

SAML.prototype.requestToUrl = function (request, operation, callback) {
    var self = this;
    var result;

    if(Meteor.settings.debug >= 2) {
        console.log("[ SAML ] Request to URL: " + operation);
    }
    if(Meteor.settings.debug >= 3) {
        console.log("[ SAML ] Request to URL, request content: " + JSON.stringify(request));
    }
    zlib.deflateRaw(request, function (err, buffer) {
        if (err) {
            return callback(err);
        }

        var base64 = buffer.toString('base64');
        var target = self.options.entryPoint;

        if (operation === 'logout') {
            if (self.options.idpSLORedirectURL) {
                target = self.options.idpSLORedirectURL;
            }
        }

        if (target.indexOf('?') > 0)
            target += '&';
        else
            target += '?';

        var samlRequest = {
            SAMLRequest: base64
        };

        samlRequest.RelayState = Meteor.absoluteUrl();
        if (self.privateCert) {
            samlRequest.SigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'; // 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
            samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
        }

        target += querystring.stringify(samlRequest);

        if (Meteor.settings.debug >= 3) {
            console.log("[ SAML ] Target URL: " + target);
        }
        if (operation === 'logout') {
            // in case of logout we want to be redirected back to the Meteor app.
            result = target;
            return callback(null, target);

        } else {
            callback(null, target);
        }
    });
}

SAML.prototype.getAuthorizeUrl = function (req, callback) {
    var request = this.generateAuthorizeRequest(req);

    if (Meteor.settings.debug >= 3) {
        console.log("[ SAML ] XML Request: " + request);
    }

    this.requestToUrl(request, 'authorize', callback);
};

SAML.prototype.getLogoutUrl = function (req, callback) {
    var request = this.generateLogoutRequest(req);

    this.requestToUrl(request, 'logout', callback);
}

SAML.prototype.certToPEM = function (cert) {
    cert = cert.match(/.{1,64}/g).join('\n');
    cert = "-----BEGIN CERTIFICATE-----\n" + cert;
    cert = cert + "\n-----END CERTIFICATE-----\n";
    return cert;
};

function findChilds(node, localName, namespace) {
    var res = []
    for (var i = 0; i < node.childNodes.length; i++) {
        var child = node.childNodes[i]
        if (child.localName == localName && (child.namespaceURI == namespace || !namespace)) {
            res.push(child)
        }
    }
    return res
}


SAML.prototype.validateSignature = function (xml, cert) {
    var self = this;

    var doc = new xmldom.DOMParser().parseFromString(xml);
    var signature = xmlCrypto.xpath(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];

    var sig = new xmlCrypto.SignedXml();

    sig.keyInfoProvider = {
        getKeyInfo: function (key) {
            return "<X509Data></X509Data>"
        },
        getKey: function (keyInfo) {
            return self.certToPEM(cert);
        }
    };

    sig.loadSignature(signature);

    return sig.checkSignature(xml);
};

SAML.prototype.getElement = function (parentElement, elementName) {
    if (parentElement['saml:' + elementName]) {
        return parentElement['saml:' + elementName];
    } else if (parentElement['samlp:' + elementName]) {
        return parentElement['samlp:' + elementName];
    } else if (parentElement['saml2p:' + elementName]) {
        return parentElement['saml2p:' + elementName];
    } else if (parentElement['saml2:' + elementName]) {
        return parentElement['saml2:' + elementName];
    } else if (parentElement['ns2:' + elementName]) {
        return parentElement['ns2:' + elementName]; 
    }
    return parentElement[elementName];
}

SAML.prototype.validateLogoutResponse = function (samlResponse, callback) {
    var self = this;

    var compressedSAMLResponse = new Buffer(samlResponse, 'base64');
    zlib.inflateRaw(compressedSAMLResponse, function (err, decoded) {

        if (err) {
            if (Meteor.settings.debug >= 1) {
                console.log("[ SAML ] Inflate SAML response failed: " + err)
            }
        } else {
            var parser = new xml2js.Parser({
                explicitRoot: true
            });
            parser.parseString(decoded, function (err, doc) {
                var response = self.getElement(doc, 'LogoutResponse');

                if (response) {
                    // TBD. Check if this msg corresponds to one we sent
                    var inResponseTo = response['$'].InResponseTo;
                    if (Meteor.settings.debug >= 3) {
                        console.log("[ SAML ] In Response to: " + inResponseTo);
                    }
                    var status = self.getElement(response, 'Status');
                    var statusCode = self.getElement(status[0], 'StatusCode')[0]['$'].Value;
                    if (Meteor.settings.debug >= 3) {
                        console.log("[ SAML ] StatusCode: " + JSON.stringify(statusCode));
                    }
                    if (statusCode === 'urn:oasis:names:tc:SAML:2.0:status:Success') {
                        // In case of a successful logout at IDP we return inResponseTo value.
                        // This is the only way how we can identify the Meteor user (as we don't use Session Cookies)
                        callback(null, inResponseTo);
                    } else {
                        callback("Error. Logout not confirmed by IDP", null);
                    }
                } else {
                    callback("No Response Found", null);
                }
            })
        }

    })




}

SAML.prototype.validateResponse = function (samlResponse, relayState, callback) {
    var self = this;
    var xml = new Buffer(samlResponse, 'base64').toString('ascii');
    // We currently use RelayState to save SAML provider
    if (Meteor.settings.debug >= 2) {
        console.log("[ SAML ] Response validation")
        if (Meteor.settings.debug >= 3) {
            console.log("[ SAML ] ... with relay state: " + xml);
        }
    }
    var parser = new xml2js.Parser({
        explicitRoot: true
    });

    parser.parseString(xml, function (err, doc) {
        // Verify signature
        if (Meteor.settings.debug >= 2) {
            console.log("[ SAML ] Signature verification");
        }
        if (self.options.cert && !self.validateSignature(xml, self.options.cert)) {
            if (Meteor.settings.debug >= 3 ) {
                console.log("[ SAML ] Signature is INVALID");
            }
            return callback(new Error('Invalid signature'), null, false);
        }
        if (Meteor.settings.debug >= 3) {
            console.log("[ SAML ] Signature is OK");
        }
        var response = self.getElement(doc, 'Response');
        if (response) {
            if (Meteor.settings.debug >= 2) {
                console.log("[ SAML ] Got response");
            }
            var assertion = self.getElement(response, 'Assertion');
            if (!assertion) {
                return callback(new Error('Missing SAML assertion'), null, false);
            }

            profile = {};

            if (response['$'] && response['$']['InResponseTo']) {
                profile.inResponseToId = response['$']['InResponseTo'];
            }

            var issuer = self.getElement(assertion[0], 'Issuer');
            if (issuer) {
                profile.issuer = issuer[0];
            }

            var subject = self.getElement(assertion[0], 'Subject');

            if (subject) {
                var nameID = self.getElement(subject[0], 'NameID');
                if (nameID) {
                    profile.nameID = nameID[0]["_"];

                    if (nameID[0]['$'].Format) {
                        profile.nameIDFormat = nameID[0]['$'].Format;
                    }
                }
            }

            var authnStatement = self.getElement(assertion[0], 'AuthnStatement');

            if (authnStatement) {
                if (Meteor.settings.debug >= 2) {
                    console.log("[ SAML ] Got AuthnStatement");
                }
                if (authnStatement[0]['$'].SessionIndex) {

                    profile.sessionIndex = authnStatement[0]['$'].SessionIndex;
                    if (Meteor.settings.debug >= 3) {
                        console.log("[ SAML ] Session Index: " + profile.sessionIndex);
                    }
                } else {
                    if (Meteor.settings.debug >= 3) {
                        console.log("[ SAML ] No Session Index Found");
                    }
                }


            } else {
                if (Meteor.settings.debug >= 2) {
                    console.log("[ SAML ] No AuthN Statement found");
                }
            }

            var attributeStatement = self.getElement(assertion[0], 'AttributeStatement');
            if (attributeStatement) {
                var attributes = self.getElement(attributeStatement[0], 'Attribute');

                if (attributes) {
                    attributes.forEach(function (attribute) {
                        var value = self.getElement(attribute, 'AttributeValue');
                        if (typeof value[0] === 'string') {
                            profile[attribute['$'].Name] = value[0];
                        } else {
                            profile[attribute['$'].Name] = value[0]['_'];
                        }
                    });
                }

                if (!profile.mail && profile['urn:oid:0.9.2342.19200300.100.1.3']) {
                    // See http://www.incommonfederation.org/attributesummary.html for definition of attribute OIDs
                    profile.mail = profile['urn:oid:0.9.2342.19200300.100.1.3'];
                }

                if (!profile.email && profile.mail) {
                    profile.email = profile.mail;
                }
            }

            if (!profile.email && profile.nameID && profile.nameIDFormat && profile.nameIDFormat.indexOf('emailAddress') >= 0) {
                profile.email = profile.nameID;
            }

            if(Meteor.settings.debug >= 3) {
                console.log("[ SAML ] Profile returned from auth provider: " + JSON.stringify(profile))
            }

            callback(null, profile, false);
        } else {
            if (Meteor.settings.debug >= 2) {
                console.log("[ SAML ] Got NO response");
            }

            var logoutResponse = self.getElement(doc, 'LogoutResponse');

            if (logoutResponse) {
                callback(null, null, true);
            } else {
                return callback(new Error('Unknown SAML response message'), null, false);
            }

        }


    });
};


SAML.prototype.generateServiceProviderMetadata = function (callbackUrl) {

    var keyDescriptor = null;

    if (!decryptionCert) {
        decryptionCert = this.options.privateCert;
    }  

    if (this.options.privateKey) {
        if (!decryptionCert) {
            throw new Error(
                "[ SAML ] Missing decryptionCert while generating metadata for decrypting service provider");
        }

        decryptionCert = decryptionCert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
        decryptionCert = decryptionCert.replace(/-+END CERTIFICATE-+\r?\n?/, '');
        decryptionCert = decryptionCert.replace(/\r\n/g, '\n');

        keyDescriptor = {
            'ds:KeyInfo': {
                'ds:X509Data': {
                    'ds:X509Certificate': {
                        '#text': decryptionCert
                    }
                }
            },
            '#list': [
        // this should be the set that the xmlenc library supports
                {
                    'EncryptionMethod': {
                        '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
                    }
                },
                {
                    'EncryptionMethod': {
                        '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
                    }
                },
                {
                    'EncryptionMethod': {
                        '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
                    }
                },
      ]
        };
    }

    if (!this.options.callbackUrl && !callbackUrl) {
        throw new Error(
            "[ SAML ] Unable to generate service provider metadata when callbackUrl option is not set");
    }

    var metadata = {
        'EntityDescriptor': {
            '@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
            '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
            '@entityID': this.options.issuer,
            'SPSSODescriptor': {
                '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
                'KeyDescriptor': keyDescriptor,
                'SingleLogoutService': {
                    '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                    '@Location': Meteor.absoluteUrl() + "_saml/logout/" + this.options.provider + "/",
                    '@ResponseLocation': Meteor.absoluteUrl() + "_saml/logout/" + this.options.provider + "/"
                },
                'NameIDFormat': this.options.identifierFormat,
                'AssertionConsumerService': {
                    '@index': '1',
                    '@isDefault': 'true',
                    '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                    '@Location': callbackUrl
                }
            },
        }
    };

    return xmlbuilder.create(metadata).end({
        pretty: true,
        indent: '  ',
        newline: '\n'
    });
};