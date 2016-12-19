/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const OSCanons = require('../lib/obfuscationService').canons;
const OSUtils = require('../lib/obfuscationService').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('IPA ObfuscationService tests', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 smoke tests', function () {

    it('1.1 should create a JSONLD node from a valid YAML version', function () {
      let md = YAML.safeLoad(readFile('obfuscationServiceValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = OSUtils.YAML2Node(md.obfuscation_service, props);

      console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.ObfuscationService), util.format('is not a Organization:%j', result));
      assert(jsonldUtils.isType(result, PN_T.Resource), util.format('is not Resource:%j', result));

      result.should.have.property(PN_P.description, 'test_description');
      result.should.have.property(PN_P.issuer, 'theIssuer');
      result.should.have.property(PN_P.creationTime, 'createTime');

      result.should.have.property(PN_P.contentObfuscationAlgorithm, 'https://ietf.org/rfc7518/A256GCM');
      result.should.have.property(PN_P.obfuscationProvider);
      result.should.have.property(PN_P.messageProtocol, PN_T.EncryptObfuscationServiceProtocolV2);
      result.should.have.property(PN_P.obfuscateEndpoint);
      result.should.have.property(PN_P.deobfuscateEndpoint);

      let verified = OSUtils.verify(result, props);
      assert(!verified, util.format('verify was not valid?:%j', verified));
    }); // 1.1

    it('1.2 canon should be valid', function () {
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = OSCanons.createTestObfuscationService(props);
      let verified = OSUtils.verify(result, props);
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.2
  }); // 1

});
