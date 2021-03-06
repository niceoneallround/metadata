/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const PAUtils = require('../lib/privacyAlgorithm').utils;
const PAlgInstanceUtils = require('../lib/PrivacyAlgorithmInstance').utils;
const PPUtils = require('../lib/privacyPipe').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('test Privacy Algorithm Instance', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 Privacy Algorithm Instance Template from a YAML file', function () {

    it('1.1 should create instance if valid params', function () {

      let md = YAML.safeLoad(readFile('privacyAlgorithmInstanceValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa' };
      let result = PAlgInstanceUtils.YAML2Node(md.privacy_algorithm_instance, props);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.PrivacyAlgorithmInstance), util.format('is not %s :%j', PN_T.PrivacyAlgorithmInstance, result));
      result.should.have.property(PN_P.description);
      result.should.have.property(PN_P.privacyAlgorithm, 'http://rs.id.webshield.io/privacy_algorithm/com/acme#palg-1');

      result.should.have.property(PN_P.privacyStepInstance);
      result[PN_P.privacyStepInstance].length.should.be.equal(1);

    }); // 1.1
  }); // describe 1

  describe('2 Privacy Algorithm Instance Template create from json', function () {

    it('2.1 should create instance if valid params', function () {

      let md = YAML.safeLoad(readFile('privacyAlgorithmInstanceValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa' };
      let fakePalgITemplate = PAlgInstanceUtils.YAML2Node(md.privacy_algorithm_instance, props);
      console.log(fakePalgITemplate);

      md = YAML.safeLoad(readFile('PAValid.yml'));
      let palg = PAUtils.YAML2Node(md.privacy_algorithm, props);
      console.log(palg);

      md = YAML.safeLoad(readFile('privacyPipeValid.yaml'));
      let pipe = PPUtils.YAML2Node(md.privacy_pipe, props);
      console.log(pipe);

      let result = PAlgInstanceUtils.create(fakePalgITemplate, palg, pipe, props);
      console.log('***', result);
      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.PrivacyAlgorithmInstance), util.format('is not %s :%j', PN_T.PrivacyAlgorithmInstance, result));
      result.should.have.property(PN_P.privacyStepInstance);
      result[PN_P.privacyStepInstance].length.should.be.equal(1);

    }); // 2.1
  }); // describe 2
});
