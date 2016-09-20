/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const MDUtils = require('../lib/md').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_T = PNDataModel.TYPE;
const YAML = require('js-yaml');
const util = require('util');

describe('test MS dispatch works', function () {
  'use strict';

  let props = { hostname: 'fake.com' };

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 MS YAML2Node tests', function () {

    it('1.1 should dispatch to the correct constructor', function () {
      let md = YAML.safeLoad(readFile('PAValid.yml'));
      let result = MDUtils.YAML2Metadata(md.privacy_algorithm, props);
      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('PA is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyAlgorithm), util.format('PA is not Metadata:%j', result));
    }); // 1.1
  }); // 1

});
