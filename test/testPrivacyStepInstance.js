/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const PStepUtils = require('../lib/privacyStep').utils;
const PStepIUtils = require('../lib/privacyStepInstance').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const PPUtils = require('../lib/privacyPipe').utils;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('test Privacy Step Instance', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 PStepInstance tests', function () {

    it('1.1 should create a Privacy Step Instance from valid params when NO privacy action instances', function () {

      let md = YAML.safeLoad(readFile('privacyStepValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa' };
      let pstep = PStepUtils.YAML2Node(md.privacy_step, props);

      // blank out fields want to set from instance
      pstep[PN_P.client] = null;
      pstep[PN_P.next] = null;
      pstep[PN_P.privacyAction] = [];

      // create the privacy pipe for obfuscate
      md = YAML.safeLoad(readFile('privacyPipeValid.yaml'));
      let pp = PPUtils.YAML2Node(md.privacy_pipe, props);

      // create the privacy action instance template
      let psit = {};
      psit['@id'] = PNDataModel.ids.createPrivacyStepInstanceId('fake.hostname', 'psit_1');
      psit['@type'] = [PN_T.PrivacyStepInstance];
      psit[PN_P.client] = 'client.com';
      psit[PN_P.next] = 'next.com';

      // create the privacy action instance
      let result = PStepIUtils.create(psit, pstep, pp, { hostname: 'fake.hostname', domainName: 'fake.domain.name' });
      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyStepInstance), util.format('is not PrivacyStepInstance:%j', result));

      result.should.have.property(PN_P.nodeType, PN_T.Connector);
      result.should.have.property(PN_P.client, 'client.com');
      result.should.have.property(PN_P.next, 'next.com');

    }); // 1.1

    it('1.2 should create a Privacy Step Instance from valid params when 1 privacy action instances', function () {

      // create the privacy step, this includes one action
      let md = YAML.safeLoad(readFile('privacyStepValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa' };
      let pstep = PStepUtils.YAML2Node(md.privacy_step, props);

      // blank out fields want to set from instance
      pstep[PN_P.client] = null;
      pstep[PN_P.next] = null;

      // create the privacy pipe, only use id so can be fake
      // create the privacy pipe for obfuscate
      md = YAML.safeLoad(readFile('privacyPipeValid.yaml'));
      let pp = PPUtils.YAML2Node(md.privacy_pipe, props);

      // create the privacy action instance template
      let pait = {};
      pait['@id'] = PNDataModel.ids.createPrivacyActionInstanceId('fake.hostname', 'pait_1');
      pait['@type'] = [PN_T.PrivacyActionInstance];
      pait[PN_P.privacyAction] = pstep[PN_P.privacyAction][0]['@id']; // only 1 action
      pait[PN_P.action] = PN_T.Obfuscate;

      // create the privacy step instance template, include the privacy action instance
      let psit = {};
      psit['@id'] = PNDataModel.ids.createPrivacyStepInstanceId('fake.hostname', 'psit_1');
      psit['@type'] = [PN_T.PrivacyStepInstance];
      psit[PN_P.client] = 'client.com';
      psit[PN_P.next] = 'next.com';
      psit[PN_P.privacyActionInstance] = [pait];

      // create the privacy step instance
      let result = PStepIUtils.create(psit, pstep, pp, props);
      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyStepInstance), util.format('is not PrivacyStepInstance:%j', result));

      result.should.have.property(PN_P.nodeType, PN_T.Connector);
      result.should.have.property(PN_P.client, 'client.com');
      result.should.have.property(PN_P.next, 'next.com');
      result.should.have.property(PN_P.privacyActionInstance);
      result[PN_P.privacyActionInstance].length.should.be.equal(1);

    }); // 1.2

    it('1.3 should create a Privacy Step Instance with 2 privacy action instances for de-obfuscate', function () {

      // create the privacy step, this includes one action
      let md = YAML.safeLoad(readFile('privacyStepValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa' };
      let pstep = PStepUtils.YAML2Node(md.privacy_step, props);

      // blank out fields want to set from instance
      pstep[PN_P.client] = null;
      pstep[PN_P.next] = null;

      // create the privacy pipe, only use id so can be fake
      // create the privacy pipe for obfuscate
      md = YAML.safeLoad(readFile('privacyPipeDeobfuscate.yaml'));
      let pp = PPUtils.YAML2Node(md.privacy_pipe, props);

      // create the privacy action instance templates
      let pait1 = {};
      pait1['@id'] = PNDataModel.ids.createPrivacyActionInstanceId('fake.hostname', 'pait_1');
      pait1['@type'] = [PN_T.PrivacyActionInstance];
      pait1[PN_P.privacyAction] = pstep[PN_P.privacyAction][0]['@id']; // only 1 action
      pait1[PN_P.action] = PN_T.Deobfuscate;
      pait1[PN_P.encryptKeyMdJWT] = 'jwt1';

      let pait2 = {};
      pait2['@id'] = PNDataModel.ids.createPrivacyActionInstanceId('fake.hostname', 'pait_2');
      pait2['@type'] = [PN_T.PrivacyActionInstance];
      pait2[PN_P.privacyAction] = pstep[PN_P.privacyAction][0]['@id']; // only 1 action
      pait2[PN_P.action] = PN_T.Deobfuscate;
      pait2[PN_P.encryptKeyMdJWT] = 'jwt2';

      // create the privacy step instance template, include the privacy action instance
      let psit = {};
      psit['@id'] = PNDataModel.ids.createPrivacyStepInstanceId('fake.hostname', 'psit_1');
      psit['@type'] = [PN_T.PrivacyStepInstance];
      psit[PN_P.client] = 'client.com';
      psit[PN_P.next] = 'next.com';
      psit[PN_P.privacyActionInstance] = [pait1, pait2];

      // create the privacy step instance
      let result = PStepIUtils.create(psit, pstep, pp, props);
      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyStepInstance), util.format('is not PrivacyStepInstance:%j', result));

      result.should.have.property(PN_P.nodeType, PN_T.Connector);
      result.should.have.property(PN_P.client, 'client.com');
      result.should.have.property(PN_P.next, 'next.com');
      result.should.have.property(PN_P.privacyActionInstance);
      result[PN_P.privacyActionInstance].length.should.be.equal(2);

    }); // 1.1
  }); // 1

  describe('2 Privacy Step Instance Template from a YAML file', function () {

    it('2.1 should create instance if valid yaml format', function () {

      let md = YAML.safeLoad(readFile('privacyStepInstanceValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa' };
      let result = PStepIUtils.YAML2Node(md.privacy_step_instance, props);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.PrivacyStepInstance), util.format('is not %s :%j', PN_T.PrivacyStepInstance, result));
      result.should.have.property(PN_P.privacyStep, 'privacy-step-id');
      result.should.have.property(PN_P.privacyActionInstance);
      result.should.have.property(PN_P.client);
      result.should.have.property(PN_P.next);
      result[PN_P.privacyActionInstance].length.should.be.equal(1);

    }); // 2.1
  }); // describe 2

});
