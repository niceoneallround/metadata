/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const ISAUtils = require('../lib/ISAlgorithm').utils;
const ISACanon = require('../lib/ISAlgorithm').canons;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('test Identity Syndicatiton Algorithm', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 ISA tests', function () {

    it('1.1 should create a ISA from a valid ISA YAML version', function () {
      let md = YAML.safeLoad(readFile('ISAlgorithmValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = ISAUtils.YAML2Node(md.is_algorithm, props);

      //console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('ISA is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.IdentitySyndicationAlgorithm), util.format('ISA is not a ISAlgorithm:%j', result));
      assert(jsonldUtils.isType(result, PN_T.Resource), util.format('ISA is not Resource:%j', result));

      result.should.have.property(PN_P.referenceSource, 'test_reference_source');
      result.should.have.property(PN_P.subjectType, 'test_subject_type');
      result.should.have.property(PN_P.description, 'test_description');
      result.should.have.property(PN_P.issuer, 'theIssuer');
      result.should.have.property(PN_P.creationTime, 'createTime');

      let verified = ISAUtils.verify(result, 'fake.hostname');
      assert(!verified, util.format('ISA was not valid?:%j', verified));
    }); // 1.1

    it('1.2 canon should be valid', function () {
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = ISACanon.createISAlgorithm(props);
      let verified = ISAUtils.verify(result, props);
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.2
  }); // 1

});
