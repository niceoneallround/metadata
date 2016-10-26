/*jslint node: true, vars: true */

const assert = require('assert');
const jsonldUtils = require('jsonld-utils/lib/jldUtils');
const moment = require('moment');
const PStepIUtils = require('./privacyStepInstance').utils;
const PNDataModel = require('data-models/lib/PNDataModel');
const PN_P = PNDataModel.PROPERTY;
const PN_T = PNDataModel.TYPE;
const util = require('util');

/*

A Privacy Algorithm Instance is created from a Privacy Algorithm at Privacy Pipe creation time,
and it contains the constant and runtime information.

It has the following properties
•	@id: a globally unique url
   https://md.pn.id.webshield.io/pstep_instance/(hostname reversed)#<id>
•	@type: [pn_t.PrivacyAlgorithmInstance]
•	pn_p.privacy_pipe: the @id of the privacy pipe that created the instance
•	pn_p.privacy_algorithm: the @id of the privacy algorithm
•	pn_p.privacy_step_instance: [<Privacy Step Instances>]

*/

var model = {};
model.utils = {};

//
// Create a Privacy Algorithm Instance from the passed in params
//
// *palgit - the privacy algorithm instance template passed in the privacy pipe
// *pstep - the privacy algorithm
// *pp - privacy pipe
// props
model.utils.create = function create(palgit, palg, pp, props) {
  'use strict';
  assert(palgit, 'palgit param is missing');
  assert(palg, 'palg param is missing');
  assert(pp, 'pp param is missing');
  assert(props.hostname, util.format('props.hostname missing - required to create ids:%j', props));
  assert(props.domainName, util.format('props.domainName missing - required to create ids:%j', props));

  let node = {};

  if (!(jsonldUtils.isType(palgit, PN_T.PrivacyAlgorithmInstance))) {
    return PNDataModel.errors.createTypeError({
      id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
      errMsg: util.format('ERROR type is not [%s] missing in:%j', PN_T.PrivacyAlgorithmInstance, palgit),
    });
  }

  node['@id'] = palgit['@id'];
  node['@type'] = [PN_T.Metadata, PN_T.PrivacyAlgorithmInstance];

  // copy constant values that are always copied
  node[PN_P.privacyAlgorithm] = palg['@id'];

  // copy variable values that are only passed at runtime
  node[PN_P.privacyPipe] = pp['@id'];

  //
  // Iterate over the privacy step instances templates
  //
  node[PN_P.privacyStepInstance] = [];
  if (palgit[PN_P.privacyStepInstance]) {

    if (palgit[PN_P.privacyStepInstance].length !== 0) {
      // Can only handle one step so check all constsistent
      if ((palgit[PN_P.privacyStepInstance].length !== 1) ||
         (palg[PN_P.privacyStep].length !== 1)) {

        return PNDataModel.errors.createTypeError({
          id: PNDataModel.ids.createErrorId(props.hostname, moment().unix()),
          errMsg: util.format(
            'ERROR privacy alg or instance have more than 1 step, or not the same number of steps alg%j Instance:%j',
            palg, palgit),
        });
      }

      // have one privacy action and one privacy action instance
      let psit = PStepIUtils.create(
                      palgit[PN_P.privacyStepInstance][0],
                      palg[PN_P.privacyStep][0],
                      pp,
                      props);

      if (PNDataModel.errors.isError(psit)) {
        return psit; // ERROR SO STOP AND RETURN;
      } else {
        node[PN_P.privacyStepInstance].push(psit);
      }
    }
  }

  return node;
};

module.exports = {
  utils:        model.utils,
};
