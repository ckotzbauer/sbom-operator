#!/bin/bash

echo "Start dockerd in background"
dockerd &
sleep 5 # TODO: Use better wait mechanism

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

    HOST=$(_jq '."registry-host"')
    USER=$(_jq '."registry-user"')
    PASSWORD=$(_jq '."registry-password"')
    IMAGE=$(_jq '."image"')
    PODS=$(_jq '."pods"')
    echo "Process image ${IMAGE}"

    if [ ! -z "${USER}" ] && [ ! -z "${PASSWORD}" ]
    then
        echo "Login to ${HOST}"
        docker login -u "${USER}" -p "${PASSWORD}" "${HOST}"
    fi

    # Join Pods, Namespaces and Clusters with "," and form the attributes for notarization.
    POD_STRING=$(echo $PODS | jq -r '[.[].pod] | join(",")')
    NAMESPACE_STRING=$(echo $PODS | jq -r '[.[].namespace] | join(",")')
    CLUSTER_STRING=$(echo $PODS | jq -r '[.[].cluster] | join(",")')

    VCN_ATTR="--attr pod=${POD_STRING} --attr namespace=${NAMESPACE_STRING} --attr cluster=${CLUSTER_STRING}"
    VCN_ARGS=("${VCN_ATTR}" "${VCN_EXTRA_ARGS:-""}" --bom docker://"${IMAGE}")

    docker pull "${IMAGE}" -q
    vcn notarize ${VCN_ARGS[@]}
    docker rm -f $(docker ps -aq)
    docker rmi "${IMAGE}"

    if [ ! -z "${USER}" ] && [ ! -z "${PASSWORD}" ]
    then
        echo "Logout from ${HOST}"
        docker logout "${HOST}"
    fi
done

vcn logout
echo "Kill dockerd"
pkill dockerd

exit $ERRORCOUNT
