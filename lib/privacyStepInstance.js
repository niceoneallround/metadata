/*jslint node: true, vars: true */

const assert = require('assert');
const BaseSubjectPNDataModel = require('data-models/lib/BaseSubjectPNDataModel'); // used for canon
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PActionIUtils = require('./privacyActionInstance').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const TRSPNDataModel = require('data-models/lib/TestReferenceSourcePNDataModel');
const util = require('util');

/*

A Privacy Step Instance is created from a Privacy Step at Privacy Pipe creation time.
It contains the fixed runtime metadata to obfuscate or de-obfuscate data.

It is created by a Privacy Broker and has the following properties
 @id: a globally unique url
   https://md.pn.id.webshield.io/pstep_instance/(hostname reversed)#<id>
 @type: [pn_t.PrivacyStepInstance]
 pn_p.privacy_pipe: the @id of the privacy pipe that created the instance
 pn_p.privacy_step: the @id of the privacy step created from
 pn_p.node_type: from the step
 pn_p.client: from either step or pipe
 pn_p.next: from either step or pipe
 pn_p.privacy_action_instance: [<Privacy Action Instances>] – based on what is in step.


*/

var model = {};
model.utils = {};
model.canons = {}; // constructors for canonical versions that can be used for test

//
// Create a Privacy Step Instance from the passed in params
//
// *psit - the privacy step instance template passed in the privacy pipe
// *pstep - the privacy step
// *pp - privacy pipe
// props
model.utils.create = function create(psit, pstep, pp, props) {
  'use strict';
  assert(psit, 'psit param is missing');
  assert(pstep, 'pstep param is missing');
  assert(pp, 'pp param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));

  let oc = pp[PN_P.obfuscationContext];
  if (!oc) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format(
        'ERROR create privacy step instance pp does not have an OC: %j', pp),
    });
  }

  let node = {};

  if (!(jsonldUtils.isType(psit, PN_T.PrivacyStepInstance))) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.PrivacyStepInstance, psit),
    });
  }

  node['@id'] = psit['@id'];
  node['@type'] = [PN_T.Metadata, PN_T.PrivacyStepInstance];

  // copy constant values that are always copied
  node[PN_P.privacyStep] = pstep['@id'];
  node[PN_P.nodeType] = pstep[PN_P.nodeType];

  // copy variable values that are only passed at runtime
  node[PN_P.privacyPipe] = pp['@id'];

  // set the client, if in the step then fixed, otherwise use one in instance
  // template
  if (pstep[PN_P.client]) {
    if (psit[PN_P.client]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR privacy step has a client cannot override in instance step%j instance:%j', pstep, psit),
      });
    } else {
      node[PN_P.client] = pstep[PN_P.client];
    }
  } else {
    node[PN_P.client] = psit[PN_P.client];
  }

  // set the next, if in the step then fixed, otherwise use one in instance
  // template
  if (pstep[PN_P.next]) {
    if (psit[PN_P.next]) {
      return PNDataModel.errors.createTypeError({
        id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
        errMsg: util.format('ERROR privacy step has a next cannot override in instance step%j instance:%j', pstep, psit),
      });
    } else {
      node[PN_P.next] = pstep[PN_P.next];
    }
  } else {
    node[PN_P.next] = psit[PN_P.next];
  }

  //
  // Iterate over the privacy action instances templates
  // Note hard coded to only handle one at the moment
  //
  node[PN_P.privacyActionInstance] = [];
  if (psit[PN_P.privacyActionInstance]) {

    if (psit[PN_P.privacyActionInstance].length !== 0) {
      // if obfuscate can only handle one action so check all constsistent
      // for de-obfuscate there may be more than one action instance for same action as parties may be using
      // the same privacy algorithm to encrypt different subjects, and a syndicated
      // subject may have from different parties - the PoC

      if (!oc[PN_P.action]) {
        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
          errMsg: util.format(
            'ERROR create privacy step instance the source pp OC does not have an action:%j  pp:%j: oc',
            oc, pp),
        });
      }

      if (oc[PN_P.action] === PN_T.Obfuscate) {
        if ((psit[PN_P.privacyActionInstance].length !== 1) ||
           (pstep[PN_P.privacyAction].length !== 1)) {

          return PNDataModel.errors.createTypeError({
            id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
            errMsg: util.format(
              'ERROR privacy step or instance have more than 1 action, or not the same number of actions step%j Instance:%j',
              pstep, psit),
          });
        }
      }

      for (let i = 0; i < psit[PN_P.privacyActionInstance].length; i++) {
        let pait = PActionIUtils.create(
                        psit[PN_P.privacyActionInstance][i],
                        pstep[PN_P.privacyAction][0], // can only be one action -  in de-obfuscate they are all for it
                        pp,
                        props);

        if (PNDataModel.errors.isError(pait)) {
          return pait; // ERROR SO STOP AND RETURN;
        } else {
          node[PN_P.privacyActionInstance].push(pait);
        }
      }

    }
  }

  return node;
};

//
// convert a YAML node into a Privacy Step Instance JSON-LD node.
// NOTE THIS IS JUST A TEMPLATE not the fully created version
// only pass in what can be overridden
//  - id
//  - privacy_step
//  - privacy_action_instance - array of action instances
//
// *yaml - the JSON version of the yaml node
// *props - var props
//
model.utils.YAML2Node = function YAML2Node(yaml, props) {
  'use strict';
  assert(yaml, 'yaml param is missing');
  assert(props, 'props param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));

  let node = {};

  if (!yaml.id) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR id missing from YAML privacy algorithm format:%j', yaml),
    });
  } else {
    node['@id'] = PNDataModel.ids.createPrivacyStepInstanceId(props.domainName, yaml.id);
  }

  node['@type'] = [PN_T.PrivacyStepInstance];

  // the @id
  if (yaml.privacy_step) {
    node[PN_P.privacyStep] = yaml.privacy_step;
  }

  // client is a CNAME by default
  if (yaml.client) {
    if (yaml.client['@type']) {
      node[PN_P.client] = yaml.client;
    } else {
      node[PN_P.client] = PNDataModel.utils.createCNameValue(yaml.client);
    }
  }

  // destination is a URL by default
  if (yaml.next) {
    if (yaml.next['@type']) {
      node[PN_P.next] = yaml.next;
    } else {
      node[PN_P.next] = PNDataModel.utils.createURLValue(yaml.next);
    }
  }

  // create the privacy action instance templates
  if (yaml.privacy_action_instance) {
    node[PN_P.privacyActionInstance] = [];

    for (let i = 0; i < yaml.privacy_action_instance.length; i++) {
      let pait = PActionIUtils.YAML2Node(yaml.privacy_action_instance[i], props);

      if (PNDataModel.errors.isError(pait)) {
        return pait; // ERROR SO STOP AND RETURN;
      } else {
        node[PN_P.privacyActionInstance].push(pait);
      }
    }
  }

  // verify the node is valid
  let error = model.utils.verifyTemplate(node, props);
  if (error) {
    return error;
  } else {
    return node;
  }
};

// ONLY VERFIY TEMPLATE properties that must be there
model.utils.verifyTemplate = function verifyTemplate(node, props) {
  'use strict';
  assert(node, 'node param missing');
  assert(props, 'props param is missing');
  assert(props.hostname, 'props.hostname is missing');

  let hostname = props.hostname;

  if (!node['@id']) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR @id missing from:%j', node),
    });
  }

  if (!jsonldUtils.isType(node, PN_T.PrivacyStepInstance)) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.PrivacyStepInstance, node),
    });
  }

  if (!node[PN_P.privacyStep]) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(hostname, moment().unix()),
      errMsg: util.format('ERROR %s missing from:%j', PN_P.privacyStep, node),
    });
  }

  // verify privacy action instance templates
  if (node[PN_P.privacyActionInstance]) {
    for (let i = 0; i < node[PN_P.privacyActionInstance]; i++) {
      let error = PActionIUtils.verifyTemplate(node[PN_P.privacyActionInstance][i], props);
      if (error) {
        return error;
      }
    }
  }

  // all ok :)
  return null;
};

//-------------------------
// Canonical Privacy Step Instance that can be used for tests
//--------------------------

function createCanonPrivacyStepI(yaml, props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  // create a JSONLD node
  let md = model.utils.YAML2Node(yaml,
              { hostname: props.hostname,
                domainName: props.domainName,
                issuer: 'fake.setin.canon', creationTime: '282828', });

  if (PNDataModel.errors.isError(md)) {
    assert(false, util.format('failed to create privacy step instance:%j', md));
  }

  //
  // FIXUP some properties that usually come from the step or action and cannot be
  // set via the yaml creation of instances.
  //
  let pai = md[PN_P.privacyActionInstance][0];
  pai[PN_P.contentObfuscationAlgorithm] = 'A256GCM'; // usually copied from action
  pai[PN_P.obfuscationProvider] = 'http://ionicsecurity.com'; // usually copied from action

  return md;
}

model.canons.createObfuscatePrivacyStepI = function createObfuscatePrivacyStepI(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'pstepi-1',
    privacy_step: 'fake-set-in-canon',
    description: 'a canon privacy step instance that can be used for testing ',
    node_type: 'connector',
    privacy_action_instance: [{
      id: 'paction-1',
      privacy_action: 'fake-set-in-canon',
      description: 'canon obfuscation privacy action instane that can be used by for testing',
      action: 'obfuscate',
      content_encrypt_key_md: 'https://md.pn.id.webshield.io/encrypt_key_md/com/fake#content-key-1', // Test EKMD does not have to exist as nock out call
      kms: 'https://md.pn.id.webshield.io/kms/com/fake#kms-1', // the canon Test KMS does not have to exist as nock out call
      skip_orchestration: false,
      schema: BaseSubjectPNDataModel.model.JSON_SCHEMA,
    },
  ],
  };

  return createCanonPrivacyStepI(yaml, props);
};

model.canons.createTestReferenceSourceObfuscatePrivacyStepI = function createTestReferenceSourceObfuscatePrivacyStepI(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'pstepi-1',
    privacy_step: 'fake-set-in-canon',
    description: 'a canon privacy step instance that can be used for testing based on test reference source schema ',
    node_type: 'connector',
    privacy_action_instance: [{
      id: 'paction-1',
      privacy_action: 'fake-set-in-canon',
      description: 'canon obfuscation privacy action instane that can be used by for testing',
      action: 'obfuscate',
      content_encrypt_key_md: 'https://md.pn.id.webshield.io/encrypt_key_md/com/fake#content-key-1', // Test EKMD does not have to exist as nock out call
      kms: 'https://md.pn.id.webshield.io/kms/com/fake#kms-1', // the canon Test KMS does not have to exist as nock out call
      skip_orchestration: false,
      schema: TRSPNDataModel.model.JSON_SCHEMA,
    },
  ],
  };

  return createCanonPrivacyStepI(yaml, props);
};

//
// --- DEOBFUSCATE CANOn
//

model.canons.createDeobfuscatePrivacyStepI = function createDeobfuscatePrivacyStepI(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'deob-pstepi-1',
    privacy_step: 'fake-set-in-canon',
    description: 'a canon deobfuscation privacy step instance that can be used for testing ',
    node_type: 'connector',
    privacy_action_instance: [{
      id: 'deob-paction-1',
      privacy_action: 'fake-set-in-canon',
      description: 'canon privacy action instane that can be used by for testing',
      action: 'deobfuscate',
      privacy_action_instance_2_deobfuscate: 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/dc#dc-paction1483568111', // set to a real looking pai so tests code works as expected
      privacy_pipe_2_deobfuscate: 'http://fake-do-not-use',
      content_encrypt_key_md: 'https://md.pn.id.webshield.io/encrypt_key_md/io/webshield/test/dc#content-key-1', // test does not need to exist as nock out call, but may awell set to the one used for testing.
      kms: 'https://md.pn.id.webshield.io/kms/com/fake#kms-1', // the canon Test KMS does not have to exist as nock out call
      skip_orchestration: false,
      schema: BaseSubjectPNDataModel.model.JSON_SCHEMA,
    },
  ],
  };

  return createCanonPrivacyStepI(yaml, props);
};

//
// Creates a Privacy Action  Instance that is based on the canon subject data in RSQueryResult
// - uses the value for privacy_action_instance_2_deobfuscate
//
model.canons.createDeobfuscateReferenceSourceSubjectsPrivacyStepI =
                function createDeobfuscateReferenceSourceSubjectsPrivacyStepI(props) {
  'use strict';

  assert(props, 'props param missing');
  assert(props.hostname, util.format('props.hostname is missing:%s', props));
  assert(props.domainName, util.format('props.domainName is missing:%j', props));

  let yaml = {
    id: 'deob-rs-subjects-pstepi-1',
    privacy_step: 'fake-set-in-canon',
    description: 'a canon deobfuscation privacy step instance for the RS Query Result subjects',
    node_type: 'connector',
    privacy_action_instance: [{
      id: 'deob-rs-subjects-paction-1',
      privacy_action: 'fake-set-in-canon',
      description: 'canon privacy action instane that can be used by for testing',
      action: 'deobfuscate',
      privacy_action_instance_2_deobfuscate: 'https://md.pn.id.webshield.io/paction_instance/io/webshield/test/rs#rspa-paction1488493433-1', // set to a real looking pai so tests code works as expected
      privacy_pipe_2_deobfuscate: 'http://fake-do-not-use',
      content_encrypt_key_md: 'https://md.pn.id.webshield.io/encrypt_key_md/io/webshield/test/dc#content-key-1', // test does not need to exist as nock out call, but may awell set to the one used for testing.
      kms: 'https://md.pn.id.webshield.io/kms/com/fake#kms-1', // the canon Test KMS does not have to exist as nock out call
      skip_orchestration: false,
      schema: TRSPNDataModel.model.JSON_SCHEMA,
    },
  ],
  };

  return createCanonPrivacyStepI(yaml, props);
};

module.exports = {
  canons: model.canons,
  utils:        model.utils,
};
