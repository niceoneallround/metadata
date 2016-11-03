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

    it('1.1 should dispatch to privacy algorithm v2', function () {
      let md = YAML.safeLoad(readFile('privacyAlgorithmV2Valid.yaml'));
      let result = MDUtils.YAML2Node(md.privacy_algorithm, props);
      let error = MDUtils.verify(result, props);
      assert(!error, util.format('PA was not valid?:%j', error));
    }); // 1.1

    it('1.2 should dispatch to reference source', function () {
      let md = YAML.safeLoad(readFile('referenceSourceValid.yaml'));
      let result = MDUtils.YAML2Node(md.reference_source, props);
      let error = MDUtils.verify(result, props);
      assert(!error, util.format('RS was not valid?:%j', error));
    }); // 1.2

    it('1.3 should dispatch to is algorithm', function () {
      let md = YAML.safeLoad(readFile('ISAlgorithmValid.yaml'));
      let result = MDUtils.YAML2Node(md.is_algorithm, props);
      let error = MDUtils.verify(result, props);
      assert(!error, util.format('ISA was not valid?:%j', error));
    }); // 1.3

    it('1.4 should dispatch to privacy algorithm instance', function () {
      let md = YAML.safeLoad(readFile('privacyAlgorithmInstanceValid.yaml'));
      let result = MDUtils.YAML2Node(md.privacy_algorithm_instance, props);
      let error = MDUtils.verify(result, props);
      assert(!error, util.format('Privacy Algorithm Instance was not valid?:%j', error));
    }); // 1.4

    it('1.5 should dispatch to provision', function () {
      let md = YAML.safeLoad(readFile('provisionValid.yaml'));
      let result = MDUtils.YAML2Node(md.provision, props);
      let error = MDUtils.verify(result, props);
      assert(!error, util.format('node was not valid?:%j', error));
    }); // 1.5

  }); // 1

  describe('2 JWTPayload2Node tests', function () {

    it('2.1 should handle a METADATA_CLAIM', function () {
      let yaml = YAML.safeLoad(readFile('privacyAlgorithmV2Valid.yaml'));
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
      let yaml = YAML.safeLoad(readFile('privacyAlgorithmV2Valid.yaml'));
      let md = MDUtils.YAML2Node(yaml.privacy_algorithm, props);

      // create JWT payload - no need to sign
      let payload = {};
      payload[JWTClaims.PN_GRAPH_CLAIM] = md;

      let node = MDUtils.JWTPayload2Node(payload, 'abc.com');
      node.should.have.property('@id', md['@id']);
    }); // 2.2

    it('2.3 should handle a PROVISION_CLAIM', function () {
      let yaml = YAML.safeLoad(readFile('provisionValid.yaml'));
      let p = MDUtils.YAML2Node(yaml.provision, props);
      let pId = p['@id'];

      // create JWT payload - no need to sign
      let payload = {};
      payload[JWTClaims.PROVISION_CLAIM] = p;
      payload[JWTClaims.PRIVACY_PIPE_CLAIM] = 'do-not-care';
      payload.sub = pId;
      p['@id'] = null; // so can check it is set
      payload.iss = 'abc.com';
      payload.iat = 12992929;

      let node = MDUtils.JWTPayload2Node(payload, 'abc.com');
      node.should.have.property('@id', pId);
      node.should.have.property(PN_P.privacyPipe);
      node.should.have.property(PN_P.provisionedMetadata);
      node.should.have.property(PN_P.issuer);
      node.should.have.property(PN_P.creationTime);
    }); // 2.3
  }); // 2

  describe('3 MS YAML2Id tests', function () {

    it('3.1 should dispatch to the correct ID constructor', function () {
      let md = YAML.safeLoad(readFile('privacyAlgorithmV2Valid.yaml'));
      let result = MDUtils.YAML2Id(md.privacy_algorithm, props);
      result.should.be.equal('https://md.pn.id.webshield.io/resource/com/fake#in-bound-palgorithm');
    }); // 3.1

    it('3.2 should dispatch to the correct ID constructor', function () {
      let md = YAML.safeLoad(readFile('referenceSourceValid.yaml'));
      let result = MDUtils.YAML2Id(md.reference_source, props);
      result.should.be.equal('https://md.pn.id.webshield.io/resource/com/fake#rs-1');
    }); // 3.2

    it('3.3 should dispatch to the correct ID constructor', function () {
      let md = YAML.safeLoad(readFile('ISAlgorithmValid.yaml'));
      let result = MDUtils.YAML2Id(md.is_algorithm, props);
      result.should.be.equal('https://md.pn.id.webshield.io/resource/com/fake#test-isa');
    }); // 3.2

  }); // 1

});
