/*jslint node: true, vars: true */

//
// THE V2 code does not change the model, just how it is constructed as
// delegates to the step and actions as opposed to having code inline
//

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const PACanons = require('../lib/privacyAlgorithmV2').canons;
const PAUtils = require('../lib/privacyAlgorithmV2').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('PAv2 Privacy Algorithm V2', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 basic tests', function () {

    it('1.1 should create a privacy alg from a valid YAML version', function () {
      let md = YAML.safeLoad(readFile('privacyAlgorithmV2Valid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = PAUtils.YAML2Node(md.privacy_algorithm, props);

      result.should.have.property('@id', 'https://md.pn.id.webshield.io/privacy_algorithm/com/fake#in-bound-palgorithm');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('PA is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyAlgorithm), util.format('PA is not PrivacyAlgorithm:%j', result));
      assert(jsonldUtils.isType(result, PN_T.Resource), util.format('PA is not Resource:%j', result));
      result.should.have.property(PN_P.description);
      result.should.have.property(PN_P.version, '2');
      result.should.have.property(PN_P.issuer, 'theIssuer');
      result.should.have.property(PN_P.creationTime, 'createTime');

      result.should.have.property(PN_P.privacyStep);
      result[PN_P.privacyStep].length.should.be.equal(1);

      let ps = result[PN_P.privacyStep][0];
      ps.should.have.property(PN_P.privacyAction);
      ps[PN_P.privacyAction].length.should.be.equal(1);

      let pa = ps[PN_P.privacyAction][0];
      pa.should.have.property('@id');
      assert(jsonldUtils.isType(pa, PN_T.PrivacyAction), util.format('PA is not PrivacyAction:%j', pa));

      //
      // It should be a valid PA if add issuer and creationTime that come from the JWT
      //
      let verified = PAUtils.verify(result, props);
      assert(!verified, util.format('PA was not valid?:%j', verified));
    }); // 1.1

    it('1.2 canon should be valid', function () {
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = PACanons.createPrivacyAlgorithm(props);
      let verified = PAUtils.verify(result, props);
      assert(!verified, util.format('PA was not valid?:%j', verified));
    }); // 1.2
  }); // 1

});
