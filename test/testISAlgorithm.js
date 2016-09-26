/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const ISAUtils = require('../lib/ISAlgorithm').utils;
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
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('PA is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.IdentitySyndicationAlgorithm), util.format('RS is not a ISAlgorithm:%j', result));
      assert(jsonldUtils.isType(result, PN_T.Resource), util.format('PA is not Resource:%j', result));

      result.should.have.property(PN_P.referenceSource, 'test_reference_source');
      result.should.have.property(PN_P.subjectType, 'test_subject_type');
      result.should.have.property(PN_P.description, 'test_description');

      let verified = ISAUtils.verify(result, 'fake.hostname');
      assert(!verified, util.format('ISA was not valid?:%j', verified));
    }); // 1.1
  }); // 1

});
