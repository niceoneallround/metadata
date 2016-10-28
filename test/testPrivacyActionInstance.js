/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const PActionUtils = require('../lib/privacyAction').utils;
const PActionIUtils = require('../lib/privacyActionInstance').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('test Privacy Action Instance', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 PActionInstance Create tests', function () {

    it('1.1 should create a PAactionInstance from valid params', function () {

      // create the privacy action
      let md = YAML.safeLoad(readFile('privacyActionValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa', privacyStep: 'fake.pstep' };
      let paction = PActionUtils.YAML2Node(md.privacy_action, props);

      // blank out fields want to set
      paction[PN_P.obfuscationService] = null;
      paction[PN_P.schema] = null;

      // create the privacy pipe, only use id so can be fake
      let pp = { '@id': 'fake.pp.id' };

      // create the privacy action instance template
      let pait = {};
      pait['@id'] = PNDataModel.ids.createPrivacyActionInstanceId('fake.hostname', 'pait_1');
      pait['@type'] = [PN_T.PrivacyActionInstance];
      pait[PN_P.privacyAction] = paction['@id'];
      pait[PN_P.action] = PN_T.Obfuscate;
      pait[PN_P.obfuscationService] = 'fake.os.id';
      pait[PN_P.schema] = 'a schema';
      pait[PN_P.encryptKeyMDJWT] = 'keymdjwt';
      pait[PN_P.encryptKeyMD] = 'keymd';

      // create the privacy action instance
      let result = PActionIUtils.create(pait, paction, pp, { hostname: 'fake.hostname', domainName: 'fake.domain.name' });
      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('PAction is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyActionInstance), util.format('PAction is not PrivacyActionInstance:%j', result));
      result.should.have.property(PN_P.privacyAction, paction['@id']);
      result.should.have.property(PN_P.action, PN_T.Obfuscate);
      result.should.have.property(PN_P.obfuscationService, 'fake.os.id');
      result.should.have.property(PN_P.schema, 'a schema');
      result.should.have.property(PN_P.encryptKeyMD, 'keymd');
      result.should.have.property(PN_P.encryptKeyMDJWT, 'keymdjwt');

    }); // 1.1
  }); // 1

  describe('2 Privacy Action Instance Template from a YAML file', function () {

    it('2.1 should create instance if valid yaml format', function () {

      let md = YAML.safeLoad(readFile('privacyActionInstanceValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa' };
      let result = PActionIUtils.YAML2Node(md.privacy_action_instance, props);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.PrivacyActionInstance), util.format('is not %s :%j', PN_T.PrivacyActionInstance, result));
      result.should.have.property(PN_P.privacyAction, 'action-1-id');
      result.should.have.property(PN_P.skipOrchestration, false);
      result.should.have.property(PN_P.obfuscationService, 'fake.os.id');
      result.should.have.property(PN_P.action);
      result.should.have.property(PN_P.schema);
      result.should.have.property(PN_P.encryptKeyMDJWT);

    }); // 2.1
  }); // describe 2

});
