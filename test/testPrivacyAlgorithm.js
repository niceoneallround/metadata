/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const PAUtils = require('../lib/privacyAlgorithm').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('test Privacy Algorithm', function () {
  'use strict';

  let props = { hostname: 'fake.com' };

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 PA tests', function () {

    it('1.1 should create a PA from a valid PA YAML version', function () {
      let md = YAML.safeLoad(readFile('PAValid.yml'));
      let result = PAUtils.YAML2PrivacyAlgorithm(md.privacy_algorithm, props);
      console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('PA is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyAlgorithm), util.format('PA is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.Resource), util.format('PA is not Metadata:%j', result));

      result.should.have.property(PN_P.privacyStep);
      result[PN_P.privacyStep].length.should.be.equal(1);

      let ps =   result[PN_P.privacyStep][0];
      ps.should.have.property(PN_P.privacyAction);
      ps[PN_P.privacyAction].length.should.be.equal(1);

    }); // 1.1
  }); // 1

});
