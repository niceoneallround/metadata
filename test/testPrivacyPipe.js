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
      result.should.have.property(PN_P.version, '2');
      result.should.have.property(PN_P.description, 'test_description');

      result.should.have.property(PN_P.client);
      result[PN_P.client].should.have.property('@value', 'client.com');

      result.should.have.property(PN_P.destination);
      result[PN_P.destination].should.have.property('@value', 'destination/url');

      result.should.have.property(PN_P.obfuscationContext);
      let oc = result[PN_P.obfuscationContext];
      oc.should.have.property('@type');
      assert(jsonldUtils.isType(oc, PN_T.ObfuscationContext), util.format('PP is not ObfuscationContext:%j', result));
      oc.should.have.property(PN_P.action, PN_T.Obfuscate);
      oc.should.have.property(PN_P.privacyAlgorithmInstanceTemplate);
      oc[PN_P.privacyAlgorithmInstanceTemplate].length.should.be.equal(1);

      let palgI = oc[PN_P.privacyAlgorithmInstanceTemplate][0];
      palgI.should.have.property('@id');
      assert(jsonldUtils.isType(palgI, PN_T.PrivacyAlgorithmInstance), util.format('PP is not:%s :%j', PN_T.PrivacyAlgorithmInstance, result));

      let verified = PPUtils.verify(result, props);
      assert(!verified, util.format('PP was not valid?:%j', verified));
    }); // 1.1
  }); // 1

});
