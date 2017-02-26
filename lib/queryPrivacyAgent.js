/*

Represents a software agent, running in an Organizations admin if control, that is querying the Identity Syndicate.

It is responsible for the orchestration of the first hop obfuscation of query data, and last hop de-obfuscation of result data.

It has the following properities
•	@id
•	@type: Resource, QueryPrivacy Agent
•	organization: the @id of the owning org
•	description
•	pndatamodel; the id of the pn data model it uses
•	privacy_algorithm: the @id of the default pipe for data sent to the US
•	provision_pipe_url
•	organization: the id of the owning organization

*/

const assert = require('assert');
const JSONLDUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

class QueryPrivacyAgent {

  //
  // convert a YAML node into a Query Privacy Agent JSON-LD node. Does not check
  // for anything other tha id as ok to have fields missing as can be added from
  // other sources, for example issuer, and creation time.
  //
  // *yaml - the JSON version of the yaml node
  //
  // optional props are
  // props.issuer: add as issuer to the PA as is not part of YAML
  // props.creationTime - add as creation time to the PA as not part of YAML
  //
  static YAML2Node(yaml, props) {
    assert(yaml, 'yaml param is missing');
    assert(props, 'props param is missing');
    assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
    assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));
    let node = {};

    if (!yaml.type) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR type missing from YAML format cannot create:%j', yaml),
      });
    }

    if (yaml.type.toLowerCase() !== 'queryprivacyagent') {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR type is not QueryPrivacyAgent:%j', yaml),
      });
    }

    // check has id
    if (!yaml.id) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR id missing from YAML format:%j', yaml),
      });
    } else {
      node['@id'] = PNDataModel.ids.createQueryPrivacyAgentId(props.domainName, yaml.id);
    }

    node['@type'] = [PN_T.Metadata, PN_T.Resource, PN_T.QueryPrivacyAgent];

    if (yaml.description) {
      node[PN_P.description] = yaml.description;
    }

    // add optional props
    if ((props) && (props.issuer)) {
      node[PN_P.issuer] = props.issuer;
    }

    if ((props) && (props.creationTime)) {
      node[PN_P.creationTime] = props.creationTime;
    }

    if (yaml.provision_pipe_url) {
      node[PN_P.provisionPipeURL] = PNDataModel.model.utils.createURLValue(yaml.provision_pipe_url);
    }

    if (yaml.pndatamodel) {
      node[PN_P.pnDataModel] = yaml.pndatamodel;
    }

    if (yaml.privacy_algorithm) {
      node[PN_P.privacyAlgorithm] = yaml.privacy_algorithm;
    }

    if (yaml.obfuscation_service) {
      node[PN_P.obfuscationService] = yaml.obfuscation_service;
    }

    if (yaml.organization) {
      node[PN_P.organization] = yaml.organization;
    }

    return node;

  }

  //--------------------------------------
  // verifier a Query Privacy Agent JSON-LD node and all its sub-nodes
  //--------------------------------------
  static verify(node, props) {
    'use strict';

    assert(node, 'node param missing');
    assert(props.hostname, util.format('props.hostname is missing:%j', props));

    let hostname = props.hostname;

    if (!node['@id']) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR @id missing from:%j', node),
      });
    }

    if (!((JSONLDUtils.isType(node, PN_T.QueryPrivacyAgent)) &&
          (JSONLDUtils.isType(node, PN_T.Metadata)) &&
          (JSONLDUtils.isType(node, PN_T.Resource))
        )) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR type is not [%s, %s, %s] missing in:%j', PN_T.QueryPrivacyAgent, PN_T.Metadata, PN_T.Resource, node),
      });
    }

    if (!node[PN_P.provisionPipeURL]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s missing from:%j', PN_P.provisionPipeURL, node),
      });
    }

    if (!node[PN_P.pnDataModel]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s missing from:%j', PN_P.pnDataModel, node),
      });
    }

    if (!node[PN_P.privacyAlgorithm]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyAlgorithm, node),
      });
    }

    if (!node[PN_P.obfuscationService]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s missing from:%j', PN_P.obfuscationService, node),
      });
    }

    if (!node[PN_P.organization]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
        errMsg: util.format('ERROR %s missing from:%j', PN_P.organization, node),
      });
    }

    // all ok :)
    return null;
  }

  //-------------------------
  // Canonical QPA can be used for tests
  //--------------------------

  static createTestQPA(props) {
    'use strict';

    assert(props, 'props param missing');
    assert(props.hostname, util.format('props.hostname is missing:%s', props));
    assert(props.domainName, util.format('props.domainName is missing:%j', props));

    let yaml = {
      id: 'test-qpa-1',
      type: 'queryprivacyagent',
      description: 'Test Query Privacy Agent',
      provision_pipe_url: 'http://query.fake.test.webshield.io/provision',
      pndatamodel: 'https://md.pn.id.webshield.io/pndatamodel/io/webshield/test/query#query', // used in testing so may aswell use
      privacy_algorithm: 'https://md.pn.id.webshield.io/privacy_algorithm/io/webshield/test/query#insecure-key-palg', // used in testing
      obfuscation_service: 'https://md.pn.id.webshield.io/obfuscation_service/io/webshield/test/query/local#os-test-private-1', // used in testing
      organization: 'https://md.pn.id.webshield.io/pndatamodel/io/webshield/test/query#test-org-1',
    };

    // create a JSONLD node
    let md = QueryPrivacyAgent.YAML2Node(yaml,
                { hostname: props.hostname,
                  domainName: props.domainName,
                  issuer: 'fake.setin.canon', creationTime: '282828', });

    if (PNDataModel.errors.isError(md)) {
      assert(false, util.format('failed to create test PNDataModel:%j', md));
    }

    return md;
  }

}

module.exports = QueryPrivacyAgent;
