/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const PActionUtils = require('../lib/privacyAction').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('PACTION test Privacy Action', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 PAction tests', function () {

    it('1.1 should create a PAaction from a valid PAction YAML version', function () {
      let md = YAML.safeLoad(readFile('privacyActionValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa', privacyStep: 'fake.pstep' };
      let result = PActionUtils.YAML2Node(md.privacy_action, props);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('PAction is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyAction), util.format('PAction is not PrivacyAction:%j', result));
      result.should.have.property(PN_P.description);

      result.should.have.property(PN_P.privacyStep, 'fake.pstep');
      result.should.have.property(PN_P.contentObfuscationAlgorithm);
      result.should.have.property(PN_P.contentEncryptKeyMD, 'http://md.pn.id.webshied.io/encrypt_key_md/com/acme#content-key-1');
      result.should.have.property(PN_P.keyEncryptKeyMD, 'http://md.pn.id.webshied.io/encrypt_key_md/com/acme#key-key-1');
      result.should.have.property(PN_P.obfuscationProvider);
      result.should.have.property(PN_P.obfuscationService);
      result.should.have.property(PN_P.kms);
      result.should.have.property(PN_P.skipOrchestration);
      result.should.have.property(PN_P.schema);

      //
      // It should be a valid PA if add issuer and creationTime that come from the JWT
      //
      let verified = PActionUtils.verify(result, props);
      assert(!verified, util.format('PAction was not valid?:%j', verified));
    }); // 1.1

    it('1.2 should nit create a PAaction from an invalid PAction YAML version', function () {
      let md = YAML.safeLoad(readFile('privacyActionValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa', privacyStep: 'fake.pstep' };

      md.privacy_action.kms = null;
      let result = PActionUtils.YAML2Node(md.privacy_action, props);
      assert(jsonldUtils.isType(result, PN_T.Error), util.format('PAction is not an Error%j', result));

    }); // 1.2
  }); // 1

});
