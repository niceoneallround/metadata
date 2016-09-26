/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const PPUtils = require('../lib/privacyPipe').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('test Privacy Pipe', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 Privacy Pipe tests', function () {

    it('1.1 should create a PP from a valid PP YAML version', function () {
      let md = YAML.safeLoad(readFile('privacyPipeValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = PPUtils.YAML2Node(md.privacy_pipe, props);

      //console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('PP is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyPipe), util.format('PP is not a PrivacyPipe:%j', result));
      assert(!jsonldUtils.isType(result, PN_T.Resource), util.format('PP should not be a Resource:%j', result));

      result.should.have.property(PN_P.description, 'test_description');

      let verified = PPUtils.verify(result, 'fake.hostname');
      assert(!verified, util.format('PP was not valid?:%j', verified));
    }); // 1.1
  }); // 1

});
