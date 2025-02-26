// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PostponedEval {
    uint256 constant MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function combineLimbs(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
        return (a + b * (1 << 125) + c * (1 << 250));
    }

    function verifyPostponedEval(uint256[] memory input, uint256 l) public pure {
        uint256[] memory postponedEval = new uint256[](3 * l);
        uint256[] memory vecToEval = new uint256[](input.length - 3 * l - 1);
        
        for (uint i = 0; i < 3 * l; i++) {
            postponedEval[i] = input[i + 1];
        }
        for (uint i = 0; i < vecToEval.length; i++) {
            vecToEval[i] = input[3 * l + 1 + i];
        }

        uint256[] memory compressedPostponedEval = new uint256[](l);
        for (uint i = 0; i < l; i++) {
            compressedPostponedEval[i] = combineLimbs(
                postponedEval[3 * i],
                postponedEval[3 * i + 1],
                postponedEval[3 * i + 2]
            );
        }

        uint256[] memory pt = new uint256[](l - 1);
        uint256 eval = compressedPostponedEval[l - 1];

        for (uint i = 0; i < l - 1; i++) {
            pt[i] = compressedPostponedEval[i];
        }

        uint256[] memory vecToEval1 = new uint256[](vecToEval.length - 60);
        uint256[] memory vecToEval2 = new uint256[](60);

        for (uint i = 0; i < vecToEval.length - 60; i++) {
            vecToEval1[i] = vecToEval[i];
        }
        for (uint i = 0; i < 60; i++) {
            vecToEval2[i] = vecToEval[vecToEval.length - 60 + i];
        }

        uint256[] memory comms = new uint256[](vecToEval2.length / 3);
        for (uint i = 0; i < comms.length; i++) {
            comms[i] = combineLimbs(
                vecToEval2[3 * i],
                vecToEval2[3 * i + 1],
                vecToEval2[3 * i + 2]
            );
        }

        uint256[] memory pubIo = new uint256[](vecToEval1.length + comms.length);
        for (uint i = 0; i < vecToEval1.length; i++) {
            pubIo[i] = vecToEval1[i];
        }
        for (uint i = 0; i < comms.length; i++) {
            pubIo[vecToEval1.length + i] = comms[i];
        }

        uint256 padLength = nextPowerOfTwo(pubIo.length);
        uint256 logPadLength = log2(padLength);

        uint256[] memory paddedPubIo = new uint256[](padLength);
        for (uint i = 0; i < pubIo.length; i++) {
            paddedPubIo[i] = pubIo[i];
        }

        uint256[] memory requiredPt = new uint256[](logPadLength);
        for (uint i = 0; i < logPadLength; i++) {
            requiredPt[i] = pt[i + pt.length - logPadLength];
        }

        uint256 computedEval = evaluateMultilinearDotProductOpt(requiredPt, paddedPubIo);

        require(eval == computedEval, "Evaluation mismatch");
    }

    function nextPowerOfTwo(uint256 x) public pure returns (uint256) {
        if (x == 0) return 1;
        return 2**(log2(x) + 1);
    }

    function log2(uint256 x) public pure returns (uint256) {
        uint256 result = 0;
        while (x > 1) {
            x >>= 1;
            result++;
        }
        return result;
    }

    function evaluateMultilinearDotProductOpt(
        uint[] memory point,
        uint[] memory coefficients
    ) public pure returns (uint256) {
        
        uint256 N = point.length;
        // Interpolate polynomial in-place (Bottom-Up)
        for (uint256 j = 0; j < N; j++) {
            uint256 stepSize = 1 << (N - j - 1); // 2^(11-j), shrinking in each iteration

            for (uint256 i = 0; i < stepSize; i++) {
                uint256 left = coefficients[2 * i];      // P_low
                uint256 right = coefficients[2 * i + 1]; // P_high

                // P' = (1 - x) * P_low + x * P_high  (mod MODULUS)
                coefficients[i] = addmod(
                    mulmod(left, addmod(1, MODULUS - point[j], MODULUS), MODULUS),
                    mulmod(right, point[j], MODULUS),
                    MODULUS
                );
            }
        }

        return coefficients[0]; // Final dot product result
    }
}
