/*jslint node: true, vars: true */

const assert = require('assert');
const BaseSubjectPNDataModel = require('data-models/lib/BaseSubjectPNDataModel');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const PNDataModelCanons = require('../lib/PNDataModel').canons;
const PNDataModelUtils = require('../lib/PNDataModel').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('PNDataModel Metadata Tests', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 PNDataModel metadata tests', function () {

    it('1.1 should create a PNDataModel from a valid PNDataModel YAML version', function () {
      let md = YAML.safeLoad(readFile('pnDataModelValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = PNDataModelUtils.YAML2Node(md.pndatamodel, props);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PNDataModel), util.format('is not a PNDataModel:%j', result));

      result.should.have.property(PN_P.description, 'test_description');
      result.should.have.property(PN_P.issuer, 'theIssuer');
      result.should.have.property(PN_P.creationTime, 'createTime');

      result.should.have.property(PN_P.subjectType, BaseSubjectPNDataModel.TYPE.Subject);

      result.should.have.property(PN_P.jsonSchema);
      (typeof result[PN_P.jsonSchema]).should.be.equal('string');
      let js = JSON.parse(result[PN_P.jsonSchema]);
      js.should.have.property('$schema');

      result.should.have.property(PN_P.jsonldContext);
      (typeof result[PN_P.jsonldContext]).should.be.equal('string');
      let jc = JSON.parse(result[PN_P.jsonldContext]);
      jc.should.have.property('id');

      result.should.have.property(PN_P.schemaPrefix);

      let verified = PNDataModelUtils.verify(result, props);
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.1

    it('1.2 canon should be valid', function () {
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = PNDataModelCanons.createTestPNDataModel(props);
      let verified = PNDataModelUtils.verify(result, props);
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.2

    it('1.3 test reference source canon should be valid', function () {
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = PNDataModelCanons.createTestReferenceSourcePNDataModel(props);
      let verified = PNDataModelUtils.verify(result, props);
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.3
  }); // 1

});
