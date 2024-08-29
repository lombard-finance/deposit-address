import * as utils from "@noble/curves/abstract/utils";
import { computeAuxDataV0 } from "../src/aux_data";

const referalData = utils.hexToBytes(
  "0000000000000000000000000000000000000000000000000000000000000000",
);

const nonces = [0xffffffff, 0xfffffffe, 0, 1];

const KATs = [
  "57302e91d7d3252be7c273a0041848c13c00b6d0782fef778f2ecab26fb0c0f8",
  "ad4abce054b9882828ac0c8003164660fd8ffc6e7005180e3e182770d4ae02c0",
  "2137aefeb756a435f07fceff39a061bd2a062b617bd8857e9c32b44ef2596bc8",
  "58bd0e282e046b08c0d395ea701678a1161f8f46362abc4a25b37dce12e57fcf",
];

test("aux data KATs", () => {
  for (let i = 0; i < nonces.length; ++i) {
    const auxData = computeAuxDataV0(nonces[i], referalData);
    const auxDataString = utils.bytesToHex(auxData);
    if (auxDataString !== KATs[i]) {
      throw new Error(`aux data mismatch in iteration ${i}`);
    }
  }
});
