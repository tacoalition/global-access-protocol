// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity 0.8.20;

contract SessionVerifier {
    /// @notice This verifier came from a DEVELOPMENT setup closed on a value published in
    ///         the repository. Its trapdoor is recoverable by anyone who can read the build
    ///         script, so proofs it accepts are NOT sound. scripts/v2/wf-ceremony.sh
    ///         is the production path. Absence of this flag proves nothing; only a
    ///         ceremony transcript does.
    bool public constant LOCAL_DEVELOPMENT_ARTIFACT = true;
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 16258229288494798437094696362526818087752290876824824194475125145530206897148;
    uint256 constant deltax2 = 3786957459311032069163738744644320211513211418920797745723269139161218831231;
    uint256 constant deltay1 = 18411872046323391854371378147889320079345402567316099335966881836378933470354;
    uint256 constant deltay2 = 5502800549329297116675995212533570608264577802732903172818243301191274474561;

    
    uint256 constant IC0x = 15280757699479938953210663615486760331314473968395869743348546062206670535065;
    uint256 constant IC0y = 40169672781348949562514060883239009015692657451183171605842333788371938618;
    
    uint256 constant IC1x = 5331899027816459509504800918407581260376216287495545480210683676385719768265;
    uint256 constant IC1y = 19921881071425652033345348523382534387872297791612623619829382139005862536279;
    
    uint256 constant IC2x = 5360971298987042729784353620055108547555037810586152183461582420581071483584;
    uint256 constant IC2y = 8035035890833537759139294585545990630656326411145113564462707395282189295554;
    
    uint256 constant IC3x = 2514405429490229524351433003646291251360174209989245538910232889510221362600;
    uint256 constant IC3y = 2533639603383286192179212054136560633539637058648899014041764300949427664861;
    
    uint256 constant IC4x = 9994867009344544870168919639555036955928710374187067416438580423718897289905;
    uint256 constant IC4y = 20122620061790194824295565133057166092405309247593223990540095882288867499721;
    
    uint256 constant IC5x = 20738964329753786042364746238361362690759460330788929784460787373046488635162;
    uint256 constant IC5y = 16882474113301861233830683879913233108552012324084814623109239312559025931524;
    
    uint256 constant IC6x = 20260204624721649108420678411079196773723682909212324385968730640527570769778;
    uint256 constant IC6y = 13594811537597516751721083743705446338473308214780647596111379033864706737320;
    
    uint256 constant IC7x = 13165620852741904689729037269395197510036897155839848556682044368442694113831;
    uint256 constant IC7y = 21205540295238848648015986626074573312566425563437565809824092276838827731621;
    
    uint256 constant IC8x = 6274245135184866485355349611493767199508305816488696650462668180739638997827;
    uint256 constant IC8y = 19101366847025521048419438239306314113376663250162271160238260704167636037125;
    
    uint256 constant IC9x = 16164404998816043931684080035646433986304215324068527990919356264783999165307;
    uint256 constant IC9y = 3407214073076651399546017059642399209928792971700964599260584302814700437509;
    
    uint256 constant IC10x = 6025950543740730866000630596749182787388830984382557275585049510441292504898;
    uint256 constant IC10y = 3573158783943002814530289694916120237017078714576955731578868603273752646428;
    
    uint256 constant IC11x = 4093244050650508743486405433250168400280242633186962479567393122608777042002;
    uint256 constant IC11y = 20529460212227677599907647160901124560047458821608529157135196458147363612479;
    
    uint256 constant IC12x = 13360585883195312838841053568710693902896492997683226314496196055885035673857;
    uint256 constant IC12y = 119281220398044243832961603694556430416221637206409107894606955693987353677;
    
    uint256 constant IC13x = 4019798174528634346797652234439407827484874085374870870904033608763095676062;
    uint256 constant IC13y = 20013133659648282614530580100263650853867211438386426191040578630512335701503;
    
    uint256 constant IC14x = 4226175951328784691653912825027074184527491438863996976830940896719755143029;
    uint256 constant IC14y = 16000476452934863544042847881852523728507067427074806025728230209756789439224;
    
    uint256 constant IC15x = 19151507036646845202781532452157162940250032218253110497478583375656910388197;
    uint256 constant IC15y = 21797970006065424681514925756069414400452471021552453073653552858475692197653;
    
    uint256 constant IC16x = 7468438306667175814979860896904395424402823409247042870942584901090421845811;
    uint256 constant IC16y = 3175505357258739136417242811215798967449266263614836499545528550140118569052;
    
    uint256 constant IC17x = 2778132457191447360842585330823708193745336910102558454087240764006288298207;
    uint256 constant IC17y = 1218789367135108314027492363417195705157396270361352514930835845621157331561;
    
    uint256 constant IC18x = 13549501115459609220972321843397849527211184823502306997060062259364959597117;
    uint256 constant IC18y = 5328839205093913699122265194941764798675806201759321077190835467143172037200;
    
    uint256 constant IC19x = 18444316650516057779525258766834091059982850652784688870695543148643950483444;
    uint256 constant IC19y = 8576706249058068887190610025113770145674959902302554194253502505107599937610;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[19] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
