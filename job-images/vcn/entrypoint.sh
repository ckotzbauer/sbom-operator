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
    echo "Process image ${IMAGE}"

    if [ ! -z "${USER}" ] && [ ! -z "${PASSWORD}" ]
    then
        echo "Login to ${HOST}"
        docker login -u "${USER}" -p "${PASSWORD}" "${HOST}"
    fi

    docker pull "${IMAGE}" -q
    vcn notarize --bom "docker://${IMAGE}"
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
