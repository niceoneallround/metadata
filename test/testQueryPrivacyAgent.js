/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const QueryPrivacyAgent = require('../lib/queryPrivacyAgent');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('test Query Privacy Agent', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 QPA tests', function () {

    let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };

    it('1.1 should create a QPA from a valid QPA YAML version', function () {
      let md = YAML.safeLoad(readFile('queryPrivacyAgentValid.yaml'));
      let result = QueryPrivacyAgent.YAML2Node(md.query_privacy_agent, props);

      //console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.QueryPrivacyAgent), util.format('is not a QueryPrivacyAgent:%j', result));
      assert(jsonldUtils.isType(result, PN_T.Resource), util.format('is not Resource:%j', result));

      result.should.have.property(PN_P.description);
      result.should.have.property(PN_P.issuer, 'theIssuer');
      result.should.have.property(PN_P.creationTime, 'createTime');

      result.should.have.property(PN_P.provisionPipeURL);
      result.should.have.property(PN_P.postQueryResultURL);
      result.should.have.property(PN_P.pnDataModel, 'test_pndatamodel');
      result.should.have.property(PN_P.privacyAlgorithm, 'test_privacy_algorithm');
      result.should.have.property(PN_P.obfuscationService, 'test_os');
      result.should.have.property(PN_P.organization, 'test_org');

      let verified = QueryPrivacyAgent.verify(result, props);
      assert(!verified, util.format('QPA was not valid?:%j', verified));
    }); // 1.1

    it('1.2 canon should be valid', function () {
      let result = QueryPrivacyAgent.createTestQPA(props);
      let verified = QueryPrivacyAgent.verify(result, props);
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.2
  }); // 1

});
