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

var prefixMatch = new RegExp(/(?!xmlns)^.*:/);



SAML = function (options) {
  this.options = this.initialize(options);
};

var stripPrefix = function(str) {
    return str.replace(prefixMatch, '');
  };

SAML.prototype.initialize = function (options) {
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
    
  return options;
};

SAML.prototype.generateUniqueID = function () {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
};

SAML.prototype.generateInstant = function () {
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + (date.getUTCHours()+2)).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
};

SAML.prototype.signRequest = function (xml) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.privateKey, 'base64');
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

  var request =
   "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" + instant +
   "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"" + callbackUrl + "\" Destination=\"" +
   this.options.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>\n";

  if (this.options.identifierFormat) {
    request += "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"" + this.options.identifierFormat +
    "\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n";
  }

  request +=
    "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
    "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
  "</samlp:AuthnRequest>";


  return request;
};

SAML.prototype.generateLogoutRequest = function (req) {
  var id = "_" + this.generateUniqueID();
  var instant = this.generateInstant();

  //samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  // ID="_135ad2fd-b275-4428-b5d6-3ac3361c3a7f" Version="2.0" Destination="https://idphost/adfs/ls/"
  //IssueInstant="2008-06-03T12:59:57Z"><saml:Issuer>myhost</saml:Issuer><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  //NameQualifier="https://idphost/adfs/ls/">myemail@mydomain.com</NameID<samlp:SessionIndex>_0628125f-7f95-42cc-ad8e-fde86ae90bbe
  //</samlp:SessionIndex></samlp:LogoutRequest>

  var request = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "+
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\""+id+"\" Version=\"2.0\" IssueInstant=\""+instant+
    "\" Destination=\""+this.options.entryPoint + "\">" +
    "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + this.options.issuer + "</saml:Issuer>"+
    "<saml:NameID Format=\""+req.user.nameIDFormat+"\">"+req.user.nameID+"</saml:NameID>"+
    "</samlp:LogoutRequest>";
  return request;
}

SAML.prototype.requestToUrl = function (request, operation, callback) {
  var self = this;
  zlib.deflateRaw(request, function(err, buffer) {
    if (err) {
      return callback(err);
    }

    var base64 = buffer.toString('base64');
    var target = self.options.entryPoint;

    if (operation === 'logout') {
      if (self.options.logoutUrl) {
        target = self.options.logoutUrl;
      }
    }

    if(target.indexOf('?') > 0)
      target += '&';
    else
      target += '?';

    var samlRequest = {
      SAMLRequest: base64
    };

    if (self.options.privateCert) {
      samlRequest.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
      samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
    }
      
    // TBD. We should really include a proper RelayState here 
    target += querystring.stringify(samlRequest) + "&RelayState=12345";
    callback(null, target);
  });
}

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  var request = this.generateAuthorizeRequest(req);

  this.requestToUrl(request, 'authorize', callback);
};

SAML.prototype.getLogoutUrl = function(req, callback) {
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
  for (var i = 0; i<node.childNodes.length; i++) {
    var child = node.childNodes[i]       
    if (child.localName==localName && (child.namespaceURI==namespace || !namespace)) {
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
  } else if (parentElement['samlp:'+elementName]) {
    return parentElement['samlp:'+elementName];
  } else if (parentElement['saml2p:'+elementName]) {
    return parentElement['saml2p:'+elementName];
  } else if (parentElement['saml2:'+elementName]) {
    return parentElement['saml2:'+elementName];
  }
  return parentElement[elementName];
}

SAML.prototype.validateResponse = function (samlResponse, relayState, callback) {
  var self = this;
  var xml = new Buffer(samlResponse, 'base64').toString('ascii');
  // TBD. We currently make to use of RelayState, but that nonce should really go in a Mongo entry
  console.log("Validating response with relay state: " + relayState);
  var parser = new xml2js.Parser({explicitRoot:true});

  var p = new xml2js.Parser({explicitRoot:true});
  p.parseString(xml, function (err, result) {
    console.log(result);
});

    parser.parseString(xml, function (err, doc) {
    // Verify signature
           console.log("Verify signature");
    if (self.options.cert && !self.validateSignature(xml, self.options.cert)) {
        console.log("Signature WRONG");
      return callback(new Error('Invalid signature'), null, false);
    }
        console.log("Signature OK");
    var response = self.getElement(doc, 'Response');
      console.log("Got response");
    if (response) {
      var assertion = self.getElement(response, 'Assertion');
      if (!assertion) {
        return callback(new Error('Missing SAML assertion'), null, false);
      }

      profile = {};

      if (response['$'] && response['$']['InResponseTo']){
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

      console.log("NameID: " + JSON.stringify(profile));

      callback(null, profile, false);
    } else {
      var logoutResponse = self.getElement(doc, 'LogoutResponse');

      if (logoutResponse){
        callback(null, null, true);
      } else {
        return callback(new Error('Unknown SAML response message'), null, false);
      }

    }


  });
};


//SAML.prototype(generateServiceProviderMetadata(options.privateCert)
SAML.prototype.generateServiceProviderMetadata = function( callbackUrl ) {
    
  var keyDescriptor = null;
    
  if (!decryptionCert) {
     decryptionCert = this.options.privateCert;   
  }
    
    
  if (this.options.privateKey) {
    if (!decryptionCert) {
      throw new Error(
        "Missing decryptionCert while generating metadata for decrypting service provider");
    }

    decryptionCert = decryptionCert.replace( /-+BEGIN CERTIFICATE-+\r?\n?/, '' );
    decryptionCert = decryptionCert.replace( /-+END CERTIFICATE-+\r?\n?/, '' );
    decryptionCert = decryptionCert.replace( /\r\n/g, '\n' );

    keyDescriptor = {
      'ds:KeyInfo' : {
        'ds:X509Data' : {
          'ds:X509Certificate': {
            '#text': decryptionCert
          }
        }
      },
      '#list' : [
        // this should be the set that the xmlenc library supports
        { 'EncryptionMethod': { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' } },
        { 'EncryptionMethod': { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' } },
        { 'EncryptionMethod': { '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' } },
      ]
    };
  }

  if (!this.options.callbackUrl && !callbackUrl) {
    throw new Error(
      "Unable to generate service provider metadata when callbackUrl option is not set");
  }

  var metadata = {
    'EntityDescriptor' : {
      '@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
      '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
      '@entityID': this.options.issuer,
      'SPSSODescriptor' : {
        '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'KeyDescriptor' : keyDescriptor,
        'NameIDFormat' : this.options.identifierFormat,
        'AssertionConsumerService' : {
          '@index': '1',
          '@isDefault': 'true',
          '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
          '@Location': callbackUrl
        }
      },
    }
  };

  return xmlbuilder.create(metadata).end({ pretty: true, indent: '  ', newline: '\n' });
};