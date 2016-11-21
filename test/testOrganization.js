/*jslint node: true, vars: true */

const assert = require('assert');
const fs = require('fs');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const OrganizationCanons = require('../lib/organization').canons;
const OrganizationUtils = require('../lib/organization').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const should = require('should');
const YAML = require('js-yaml');
const util = require('util');

describe('Organization tests', function () {
  'use strict';

  function readFile(mdFile) {
    return fs.readFileSync(__dirname + '/data/' + mdFile, 'utf8');
  }

  describe('1 smoke tests', function () {

    it('1.1 should create a JSONLD node from a valid YAML version', function () {
      let md = YAML.safeLoad(readFile('organizationValid.yaml'));
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = OrganizationUtils.YAML2Node(md.organization, props);

      console.log(result);

      result.should.have.property('@id');
      result.should.have.property('@type');
      assert(jsonldUtils.isType(result, PN_T.Metadata), util.format('is not Metadata:%j', result));
      assert(jsonldUtils.isType(result, PN_T.Organization), util.format('is not a Organization:%j', result));
      assert(jsonldUtils.isType(result, PN_T.Resource), util.format('is not Resource:%j', result));

      result.should.have.property(PN_P.description, 'test_description');
      result.should.have.property(PN_P.name, 'test_name');
      result.should.have.property(PN_P.domainName, 'test_domain_name');
      result.should.have.property(PN_P.issuer, 'theIssuer');
      result.should.have.property(PN_P.creationTime, 'createTime');

      let verified = OrganizationUtils.verify(result, 'fake.hostname');
      assert(!verified, util.format('verify was not valid?:%j', verified));
    }); // 1.1

    it('1.2 canon should be valid', function () {
      let props = { hostname: 'fake.hostname', domainName: 'fake.com', issuer: 'theIssuer', creationTime: 'createTime' };
      let result = OrganizationCanons.createTestOrganization(props);
      let verified = OrganizationUtils.verify(result, props);
      assert(!verified, util.format('was not valid?:%j', verified));
    }); // 1.2
  }); // 1

});
