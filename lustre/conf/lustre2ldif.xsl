<?xml version="1.0" encoding="iso-8859-1"?>
<stylesheet version="1.0" xmlns="http://www.w3.org/1999/XSL/Transform"> 
<output omit-xml-declaration="yes" />
<strip-space elements="*"/>
<param name="config">fs=lustre</param>
<variable name="basedn">config=<value-of select="$config"/>,fs=lustre</variable>

<template match="lustre">
dn: <value-of select="$basedn"/>
uuid: CONFIG_UUID
objectClass: LUSTRECONFIG
config: <value-of select="$config"/>
version: <value-of select="@version"/>
<text>
</text><apply-templates/>
</template>

<template match="node">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: NODE
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
networkRef: <value-of select="network/@uuid"/>
<for-each select="profile_ref">
profileRef: <value-of select="@uuidref"/>
</for-each>
<if test="timeout">
timeout: <value-of select="timeout"/>
</if>
<if test="lustreUpcall">
lustreUpcall: <value-of select="lustreUpcall"/>
</if>
<if test="portalsUpcall">
portalsUpcall: <value-of select="portalsUpcall"/>
</if>
<if test="ptldebug">
ptldebug: <value-of select="ptldebug"/>
</if>
<if test="subsystem">
subsystem: <value-of select="subsystem"/>
</if>
<text>
</text>
<for-each select="network">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: NETWORK
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
nettype: <value-of select="@nettype"/>
nid: <value-of select="nid"/>
<if test="port">
port: <value-of select="port"/>
</if>
<text>
</text>
</for-each>
</template>

<template match="profile">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: PROFILE
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/><apply-templates/>
<text>
</text>
</template>

<template match="network">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: NETWORK
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
nettype: <value-of select="@nettype"/>
nid: <value-of select="nid"/>
<if test="port">
port: <value-of select="port"/>
</if>
<text>
</text>
</template>


<template match="mds">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: MDS
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
activeRef: <value-of select="active_ref/@uuidref"/>
<if test="lovconfig_ref">
lovconfigRef: <value-of select="lovconfig_ref/@uuidref"/>
</if>
<if test="filesystem_ref">
filesystemRef: <value-of select="filesystem_ref/@uuidref"/>
</if>
<if test="@failover">
failover: <value-of select="@failover"/>
</if>
<if test="group">
group: <value-of select="group"/>
</if>
<text>
</text>
</template>

<template match="mdsdev">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: MDSDEV
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
<if test="fstype">
fstype: <value-of select="fstype"/>
</if>
<if test="autoformat">
autoformat: <value-of select="autoformat"/>
</if>
<if test="devpath">
devpath: <value-of select="devpath"/>
</if>
<if test="devsize">
devsize: <value-of select="devsize"/>
</if>
<if test="journalsize">
journalsize: <value-of select="journalsize"/>
</if>
<if test="mkfsoptions">
mkfsoptions: <value-of select="mkfsoptions"/>
</if>
<if test="mountfsoptions">
mountfsoptions: <value-of select="mountfsoptions"/>
</if>
nodeRef: <value-of select="node_ref/@uuidref"/>
targetRef: <value-of select="target_ref/@uuidref"/>
<text>
</text>
</template>

<template match="lov">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: LOV
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
mdsRef: <value-of select="mds_ref/@uuidref"/>
stripepattern: <value-of select="@stripepattern"/>
stripesize: <value-of select="@stripesize"/>
stripecount: <value-of select="@stripecount"/><apply-templates/>
<text>
</text>
</template>

<template match="lovconfig">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: LOVCONFIG
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/><apply-templates/>
<text>
</text>
</template>

<template match="osd">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: OSD
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
nodeRef: <value-of select="node_ref/@uuidref"/>
targetRef: <value-of select="target_ref/@uuidref"/>
osdtype: <value-of select="@osdtype"/>
<if test="fstype">
fstype: <value-of select="fstype"/>
</if>
<if test="autoformat">
autoformat: <value-of select="autoformat"/>
</if>
<if test="devpath">
devpath: <value-of select="devpath"/>
</if>
<if test="devsize">
devsize: <value-of select="devsize"/>
</if>
<if test="journalsize">
journalsize: <value-of select="journalsize"/>
</if>
<if test="mkfsoptions">
mkfsoptions: <value-of select="mkfsoptions"/>
</if>
<if test="mountfsoptions">
mountfsoptions: <value-of select="mountfsoptions"/>
</if>
<text>
</text>
</template>

<template match="ost">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: OST
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
activeRef: <value-of select="active_ref/@uuidref"/>
<if test="@failover">
failover: <value-of select="@failover"/>
</if>
<if test="group">
group: <value-of select="group"/>
</if>
<text>
</text>
</template>

<template match="filesystem">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: FILESYSTEM
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/><apply-templates/>
<text>
</text>
</template>

<template match="mountpoint">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: MOUNTPOINT
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/><apply-templates/>
<if test="clientoptions">
clientoptions: <value-of select="clientoptions"/>
</if>
<text>
</text>
</template>

<template match="echoclient">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: ECHOCLIENT
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/><apply-templates/>
<text>
</text>
</template>

<template match="ldlm">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: LDLM
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
<text>
</text>
</template>

<template match="ptlrpc">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: PTLRPC
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
<text>
</text>
</template>

<template match="ldlm_ref">
ldlmRef: <value-of select="@uuidref"/>
</template>

<template match="ptlrpc_ref">
ptlrpcRef: <value-of select="@uuidref"/>
</template>

<template match="obd_ref">
obdRef: <value-of select="@uuidref"/>
</template>

<template match="osd_ref">
osdRef: <value-of select="@uuidref"/>
</template>

<template match="ost_ref">
ostRef: <value-of select="@uuidref"/>
</template>

<template match="network_ref">
networkRef: <value-of select="@uuidref"/>
</template>

<template match="mds_ref">
mdsRef: <value-of select="@uuidref"/>
</template>

<template match="mdsdev_ref">
mdsdevRef: <value-of select="@uuidref"/>
</template>

<template match="mountpoint_ref">
mountpointRef: <value-of select="@uuidref"/>
</template>

<template match="filesystem_ref">
filesystemRef: <value-of select="@uuidref"/>
</template>

<template match="echoclient_ref">
echoclientRef: <value-of select="@uuidref"/>
</template>

<template match="lov_ref">
lovRef: <value-of select="@uuidref"/>
</template>

<template match="path">
path: <value-of select="."/>
</template>

</stylesheet>
