/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const JWTClaims = require('jwt-utils/lib/jwtUtils').claims;
const MDUtils = require('../lib/md').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const YAML = require('js-yaml');
const util = require('util');

describe('test MS dispatch works', function () {
  'use strict';

  let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'abc.com', creationTime: '1221' };

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 MS YAML2Node tests', function () {

    it('1.1 should dispatch to the correct constructor', function () {
      let md = YAML.safeLoad(readFile('PAValid.yml'));
      let result = MDUtils.YAML2Node(md.privacy_algorithm, props);
      let error = MDUtils.verify(result, props);
      assert(!error, util.format('PA was not valid?:%j', error));
    }); // 1.1

    it('1.2 should dispatch to the correct constructor', function () {
      let md = YAML.safeLoad(readFile('referenceSourceValid.yaml'));
      let result = MDUtils.YAML2Node(md.reference_source, props);
      let error = MDUtils.verify(result, props);
      assert(!error, util.format('RS was not valid?:%j', error));
    }); // 1.2

  }); // 1

  describe('2 JWTPayload2Node tests', function () {

    it('2.1 should handle a METADATA_CLAIM', function () {
      let yaml = YAML.safeLoad(readFile('PAValid.yml'));
      let md = MDUtils.YAML2Node(yaml.privacy_algorithm, props);
      let mdId = md['@id'];

      // create JWT payload - no need to sign
      let payload = {};
      payload[JWTClaims.METADATA_CLAIM] = md;
      payload.sub = mdId;
      md['@id'] = null; // so can check it is set
      payload.iss = 'abc.com';
      payload.iat = 12992929;

      let node = MDUtils.JWTPayload2Node(payload, 'abc.com');
      node.should.have.property('@id', mdId);
      node.should.have.property(PN_P.issuer);
      node.should.have.property(PN_P.creationTime);
    }); // 2.1

    it('2.2 should handle a PN_GRAPH_CLAIM', function () {
      let yaml = YAML.safeLoad(readFile('PAValid.yml'));
      let md = MDUtils.YAML2Node(yaml.privacy_algorithm, props);

      // create JWT payload - no need to sign
      let payload = {};
      payload[JWTClaims.PN_GRAPH_CLAIM] = md;

      let node = MDUtils.JWTPayload2Node(payload, 'abc.com');
      node.should.have.property('@id', md['@id']);
    }); // 2.2
  }); // 2

});
