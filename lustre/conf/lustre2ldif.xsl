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
<text>
</text><apply-templates/>
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
uuid: <value-of select="@uuid"/><apply-templates/>
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
networkRef: <value-of select="network_ref/@uuidref"/>
mdsRef: <value-of select="mds_ref/@uuidref"/>
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

<template match="obd">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: OBD
lustreName: <value-of select="@name"/>
uuid: <value-of select="@uuid"/>
activeRef: <value-of select="active_ref/@uuidref"/>
obdtype: <value-of select="@obdtype"/>
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
<text>
</text>
</template>

<template match="ost">
dn: uuid=<value-of select="@uuid"/>,<value-of select="$basedn"/>
objectClass: OST
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


<template match="ldlm_ref">
ldlmRef: <value-of select="@uuidref"/>
</template>

<template match="obd_ref">
obdRef: <value-of select="@uuidref"/>
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

<template match="echoclient_ref">
echoclientRef: <value-of select="@uuidref"/>
</template>

<template match="lov_ref">
lovRef: <value-of select="@uuidref"/>
</template>

<template match="lovconfig_ref">
lovconfigRef: <value-of select="@uuidref"/>
</template>

<template match="path">
path: <value-of select="."/>
</template>

<template match="active_ref">
activeRef: <value-of select="@uuidref"/>
</template>
</stylesheet>


