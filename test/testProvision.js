/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const provisionUtils = require('../lib/provision').utils;
const ProvisionCanons = require('../lib/provision').canons;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('test Provision', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 Provision tests', function () {

    it('1.1 should create a provision from a valid YAML version', function () {
      let md = YAML.safeLoad(readFile('provisionValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = provisionUtils.YAML2Node(md.provision, props);

      //console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Provision), util.format('is not Provision:%j', result));

      result.should.have.property(PN_P.provisionedMetadata, ['test_md1', 'test_md2']);
      result.should.have.property(PN_P.privacyPipe, 'test_pipe');
      result.should.have.property(PN_P.description, 'test_description');

      let verified = provisionUtils.verify(result, 'fake.hostname');
      assert(!verified, util.format('node was not valid?:%j', verified));
    }); // 1.1

    it('1.2 should convert metadata to a array if not already', function () {
      let md = {
        id: 'test-provision',
        type: 'provision',
        description: 'test_description',
        provisioned_metadata: 'test_md1',
        privacy_pipe: 'test_pipe',
      };

      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = provisionUtils.YAML2Node(md, props);

      //console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Provision), util.format('is not Provision:%j', result));

      result.should.have.property(PN_P.provisionedMetadata, ['test_md1']);
      result.should.have.property(PN_P.privacyPipe, 'test_pipe');
      result.should.have.property(PN_P.description, 'test_description');

      let verified = provisionUtils.verify(result, 'fake.hostname');
      assert(!verified, util.format('node was not valid?:%j', verified));
    }); // 1.2
  }); // 1

  describe('2 Canon Tests', function () {

    it('2.1 should return a provision with an de-obfuscate psi for the canon syndicate request subjects', function () {
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', privacyPipeId: 'pipe1', };
      let provision = ProvisionCanons.createDebofuscateIngestPASubjectsProvision(props);

      let verified = provisionUtils.verify(provision, 'fake.hostname');
      assert(!verified, util.format('node was not valid?:%j', verified));
    }); // 2.1

    it('2.2 should return a provision with an de-obfuscate psi for the canon reference source query result subjects', function () {
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', privacyPipeId: 'pipe1', };
      let provision = ProvisionCanons.createDebofuscateReferenceSourceSubjectsProvision(props);

      let verified = provisionUtils.verify(provision, 'fake.hostname');
      assert(!verified, util.format('node was not valid?:%j', verified));
    }); // 2.1
  }); // 2

});
