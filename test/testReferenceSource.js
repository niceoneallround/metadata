/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const RSUtils = require('../lib/referenceSource').utils;
const RSCanons = require('../lib/referenceSource').canons;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('test Reference Source', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 RS tests', function () {

    it('1.1 should create a RS from a valid RS YAML version', function () {
      let md = YAML.safeLoad(readFile('referenceSourceValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = RSUtils.YAML2Node(md.reference_source, props);

      //console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('PA is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.ReferenceSource), util.format('RS is not a ReferenceSource:%j', result));
      assert(jsonldUtils.isType(result, PN_T.Resource), util.format('PA is not Resource:%j', result));

      result.should.have.property(PN_P.description);
      result.should.have.property(PN_P.issuer, 'theIssuer');
      result.should.have.property(PN_P.creationTime, 'createTime');

      result.should.have.property(PN_P.provisionPipeURL);
      result.should.have.property(PN_P.subjectQueryURL);
      result.should.have.property(PN_P.pnDataModel, 'test_pndatamodel');
      result.should.have.property(PN_P.privacyAlgorithm, 'test_privacy_algorithm');
      result.should.have.property(PN_P.obfuscationService, 'test_os');

      let verified = RSUtils.verify(result, 'fake.hostname');
      assert(!verified, util.format('RS was not valid?:%j', verified));
    }); // 1.1

    it('1.3 canon should be valid', function () {
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = RSCanons.createTestReferenceSource(props);
      let verified = RSUtils.verify(result, props);
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.2
  }); // 1

});
