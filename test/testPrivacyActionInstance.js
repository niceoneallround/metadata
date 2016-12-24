/*jslint node: true, vars: true */

const assert = require('assert');
const BaseSubjectPNDataModel = require('data-models/lib/BaseSubjectPNDataModel');
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

describe('PACTIONI test Privacy Action Instance', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 PActionInstance Create tests', function () {

    it('1.1 should create a PAactionInstance from a paiTemplate, privacy action, and pp', function () {

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
      pait[PN_P.encryptKeyMD] = 'keymdId';

      // create the privacy action instance
      let result = PActionIUtils.create(pait, paction, pp, { hostname: 'fake.hostname', domainName: 'fake.domain.name' });
      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('PAction is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyActionInstance), util.format('PAction is not PrivacyActionInstance:%j', result));
      result.should.have.property(PN_P.privacyAction, paction['@id']);
      result.should.have.property(PN_P.action, PN_T.Obfuscate);
      result.should.have.property(PN_P.obfuscationService, 'fake.os.id');
      result.should.have.property(PN_P.obfuscationProvider);
      result.should.have.property(PN_P.contentObfuscationAlgorithm);
      result.should.have.property(PN_P.contentEncryptKeyMD, 'http://md.pn.id.webshied.io/encrypt_key_md/com/acme#content-key-1');
      result.should.have.property(PN_P.keyEncryptKeyMD, 'http://md.pn.id.webshied.io/encrypt_key_md/com/acme#key-key-1');
      result.should.have.property(PN_P.schema, 'a schema');

    }); // 1.1
  }); // 1

  describe('2 Privacy Action Instance Template from a YAML file', function () {

    it('2.1 should create an obfuscate instance if valid yaml format', function () {

      let md = YAML.safeLoad(readFile('privacyActionInstanceValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa' };
      let result = PActionIUtils.YAML2Node(md.privacy_action_instance, props);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.PrivacyActionInstance), util.format('is not %s :%j', PN_T.PrivacyActionInstance, result));
      result.should.have.property(PN_P.privacyAction, 'action-1-id');
      result.should.have.property(PN_P.skipOrchestration, false);
      result.should.have.property(PN_P.obfuscationService, 'fake.os.id');
      result.should.have.property(PN_P.action, PN_T.Obfuscate);
      result.should.have.property(PN_P.schema);
      result.should.have.property(PN_P.contentEncryptKeyMD, 'http://md.pn.id.webshied.io/encrypt_key_md/com/acme#content-key-1');
      result.should.have.property(PN_P.keyEncryptKeyMD, 'http://md.pn.id.webshied.io/encrypt_key_md/com/acme#key-key-1');
    }); // 2.1

    it('2.2 should create a de-obfuscate instance if valid yaml format', function () {

      let md = YAML.safeLoad(readFile('privacyActionInstanceDeobfuscate.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa' };
      let result = PActionIUtils.YAML2Node(md.privacy_action_instance, props);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.PrivacyActionInstance), util.format('is not %s :%j', PN_T.PrivacyActionInstance, result));
      result.should.have.property(PN_P.privacyAction, 'action-1-id');
      result.should.have.property(PN_P.skipOrchestration, false);
      result.should.have.property(PN_P.obfuscationService, 'fake.os.id');
      result.should.have.property(PN_P.action, PN_T.Deobfuscate);
      result.should.have.property(PN_P.privacyActionInstance2Deobfuscate, '1');
      result.should.have.property(PN_P.privacyPipe2Deobfuscate, '2');
      result.should.have.property(PN_P.schema);
      (typeof result[PN_P.schema]).should.be.equal('string');
      let js = JSON.parse(result[PN_P.schema]);
      js.should.have.property('$schema');

      result.should.have.property(PN_P.contentEncryptKeyMD, 'http://md.pn.id.webshied.io/encrypt_key_md/com/acme#content-key-1');
      result.should.have.property(PN_P.keyEncryptKeyMD, 'http://md.pn.id.webshied.io/encrypt_key_md/com/acme#key-key-1');

    }); // 2.2

    it('2.3 create from YAML format passing in a schema with typeof object as was having a bug with this', function () {

      let schema = BaseSubjectPNDataModel.model.JSON_SCHEMA;
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa' };
      let paiYAML = {
        id: 'privacy-action-instance-1',
        privacy_action: 'action-1-id',
        obfuscation_service: 'fake.os.id',
        skip_orchestration: false,
        action: 'obfuscate',
        schema: schema,
        encrypt_key_md_jwt: 'keymd_jwt',
      };

      let result = PActionIUtils.YAML2Node(paiYAML, props);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.PrivacyActionInstance), util.format('is not %s :%j', PN_T.PrivacyActionInstance, result));
      (typeof result[PN_P.schema]).should.be.equal('string');
      let js = JSON.parse(result[PN_P.schema]);
      js.should.have.property('$schema');
      js.should.have.property('title');

    }); // 2.3
  }); // describe 2

});
