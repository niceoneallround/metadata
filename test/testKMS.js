/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const KMSUtils = require('../lib/KMS').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('KMS Resource Tests', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 KMS tests', function () {

    it('1.1 should create a KMS from a valid KMS YAML version', function () {
      let md = YAML.safeLoad(readFile('kmsValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = KMSUtils.YAML2Node(md.kms, props);

      console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.KMS), util.format('is not a KMS:%j', result));
      assert(jsonldUtils.isType(result, PN_T.Resource), util.format('is not aResource:%j', result));

      result.should.have.property(PN_P.provider, 'https://kms.test.webshield.io/insecure');
      result.should.have.property(PN_P.algorithm);
      result.should.have.property(PN_P.description, 'test_description');
      result.should.have.property(PN_P.issuer, 'theIssuer');
      result.should.have.property(PN_P.creationTime, 'createTime');

      result.should.have.property(PN_P.customProps);
      result[PN_P.customProps].should.have.property('http://pn.schema.webshield.io/prop#dummy_prop', 'hello');

      let verified = KMSUtils.verify(result, 'fake.hostname');
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.1
  }); // 1

});
