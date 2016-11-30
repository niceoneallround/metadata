/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const EKMDUtils = require('../lib/encryptKeyMetadata').utils;
const EKMDCanons = require('../lib/encryptKeyMetadata').canons;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('EKMD Encrypt Key Metadata Tests', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 EKMD tests', function () {

    it('1.1 should create an EKMD from a valid YAML version', function () {
      let md = YAML.safeLoad(readFile('encryptKeyMDValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = EKMDUtils.YAML2Node(md.encrypt_key_metadata, props);

      //console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.EncryptKeyMetadata), util.format('is not a %s:%j', PN_T.EncryptKeyMetadata, result));

      result.should.have.property(PN_P.description);
      result.should.have.property(PN_P.issuer, 'theIssuer');
      result.should.have.property(PN_P.creationTime, 'createTime');

      result.should.have.property(PN_P.rawEncryptKeyMetadata);

      // convert back from base64 and make sure ok
      let s = Buffer.from(result[PN_P.rawEncryptKeyMetadata], 'base64');
      let j = JSON.parse(s);
      j.should.have.property('kty', 'oct');
      j.should.have.property('alg', 'AES_256');
      j.should.have.property('k', '2kW2pzVjo1n+hpDuNnZTRy4CjXqAkgMQ1MtpWZFd4FI=');

      let verified = EKMDUtils.verify(result, props);
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.1

    it('1.2 canon should be valid', function () {
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = EKMDCanons.createTestKey(props);
      let verified = EKMDUtils.verify(result, props);
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.2

  }); // 1

});
