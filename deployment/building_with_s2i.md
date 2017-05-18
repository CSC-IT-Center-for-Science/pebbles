# How to use s2i to build a Pebbles docker image

## Building locally

- install s2i from https://github.com/openshift/source-to-image/releases
- build the image from local directory with python 2.7 builder 

``` bash
    s2i build --copy . centos/python-27-centos7 cscfi/pebbles
```

## Building in OpenShift

OpenShift can be used for building and distributing the images 

### Create a build with CLI
- prerequisite: access to the cluster
- create a new build from cli for master branch

``` bash
    oc new-build centos/python-27-centos7~https://github.com/CSCfi/pebbles#master --name pebbles
```

### Create a build from Web UI

- click on 'Add to project'
- go to 'Import YAML / JSON'
- paste the following:

```yaml
apiVersion: v1
kind: BuildConfig
metadata:
  name: pebbles
spec:
  output:
    to:
      kind: ImageStreamTag
      name: pebbles:latest
  postCommit: {}
  resources: {}
  runPolicy: Serial
  source:
    git:
      ref: master
      uri: https://github.com/CSCfi/pebbles
    type: Git
  strategy:
    sourceStrategy:
      from:
        kind: ImageStreamTag
        name: python-27-centos7:latest
    type: Source
  triggers:
  - type: ConfigChange
  - type: ImageChange
    imageChange: {}
```

- to enable GitHub webhooks
  - go to the Build page
  - select 'Actions -> Edit'
  - click 'Show advanced Options'
  - for further info, see https://docs.openshift.org/latest/dev_guide/builds/triggering_builds.html
