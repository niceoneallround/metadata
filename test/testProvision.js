/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const provisionUtils = require('../lib/provision').utils;
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
  }); // 1

});
