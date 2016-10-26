/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const PStepUtils = require('../lib/privacyStep').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('test Privacy Action', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 PStep tests', function () {

    it('1.1 should create a privacy step from a valid YAML version', function () {
      let md = YAML.safeLoad(readFile('privacyStepValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', pa: 'fake.pa', privacyStep: 'fake.pstep' };
      let result = PStepUtils.YAML2Node(md.privacy_step, props);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.PrivacyStep), util.format('is not PrivacyStep:%j', result));
      result.should.have.property(PN_P.description);
      result.should.have.property(PN_P.nodeType);
      result.should.have.property(PN_P.client);
      result.should.have.property(PN_P.next);
      result.should.have.property(PN_P.privacyAction);

      //
      // It should be a valid PA if add issuer and creationTime that come from the JWT
      //
      let verified = PStepUtils.verify(result, props);
      assert(!verified, util.format('PStep was not valid?:%j', verified));
    }); // 1.1

  }); // 1

});
