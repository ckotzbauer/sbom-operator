#!/bin/bash

ERRORCOUNT=0
inc_errors() {
    (( ERRORCOUNT += 1 ))
}
trap 'inc_errors' ERR

vcn login

CONFIG=$(cat /sbom/image-config.json)
for img in $(echo "${CONFIG}" | jq -r '.[] | @base64'); do
     _jq() {
         echo "${img}" | base64 -d | jq -r ${1}
     }

    USER=$(_jq '."registry-user"')
    PASSWORD=$(_jq '."registry-password"')
    IMAGE=$(_jq '."image"')
    PODS=$(_jq '."pods"')
    echo "Process image ${IMAGE}"
    VCN_PULL_CREDS=""

    if [ ! -z "${USER}" ] && [ ! -z "${PASSWORD}" ]
    then
        VCN_PULL_CREDS="--image-registry-user ${USER} --image-registry-password ${PASSWORD}"
        echo "Using provided pull-credentials"
    fi

    # Join Pods, Namespaces and Clusters with "," and form the attributes for notarization.
    POD_STRING=$(echo $PODS | jq -r '[.[].pod] | join(",")')
    NAMESPACE_STRING=$(echo $PODS | jq -r '[.[].namespace] | join(",")')
    CLUSTER_STRING=$(echo $PODS | jq -r '[.[].cluster] | join(",")')

    VCN_ATTR="--attr pod=${POD_STRING} --attr namespace=${NAMESPACE_STRING} --attr cluster=${CLUSTER_STRING}"
    VCN_ARGS=("${VCN_PULL_CREDS}" "${VCN_ATTR}" "${VCN_EXTRA_ARGS:-""}" --bom image://"${IMAGE}")

    vcn notarize ${VCN_ARGS[@]}
done

vcn logout
exit $ERRORCOUNT
