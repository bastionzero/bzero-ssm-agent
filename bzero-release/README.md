# Bzero Agent Release Process (Internal Only)

In order to release a new version of the agent the following steps can be taken:

1. Merge feature branch to `bzero-dev` branch.

2. Tag the release commit with a tag in the form `bzero-<agent-version>`. For example `bzero-3.0.732.15`. We are following the version naming convention where the first 3 numbers are the upstream amazon-ssm-agent version we are based on followed by the last number being the specific bzero release version.

3. Start a new AWS CodePipeline execution for the [bzero-ssm-agent-pipeline](https://console.aws.amazon.com/codesuite/codepipeline/pipelines/bzero-ssm-agent-pipeline). This will immediately start a codebuild build job as the fist stage of the pipeline.

    + Click `Release Change` button in the top right which will start a new pipeline execution.
    + The source code will be the most recent commit in the `bzero-dev` branch, however the build job will look back in history for the last commit that was tagged and checkout this commit specifically.
    + The build job will build and package the agent to create the set of [build artifacts](#Build-Artifacts) that are later published to s3 in the pipeline.

4. Once the build stage has completed, another stage to publish a new agent version should automatically start and publish artifacts to s3. These can be accessed through a cloudfront distribution at: `https://download-ssm-agent.bastionzero.com/release/<agent-version>`.

5. Next, a manual approve step is needed in the pipeline in order to publish to staging which will copy the same set of artifacts to `https://download-ssm-agent.bastionzero.com/release/staging`. This will additionally invalidate the cloudfront distribution cache for the /release/staging path to ensure new requests will be returned the newest agent.

6. Finally, a final manual approve step is needed in the pipeline in order to publish to production which will copy the same set of artifacts to `https://download-ssm-agent.bastionzero.com/release/latest`. This will additionally invalidate the cloudfront distribution cache for the /release/latest path to ensure new requests will be returned the newest agent.


# Build Artifacts

Currently build artifacts include rpm package and debian (dpkg) package for both arm64 and x86_64 architectures. The build artifacts directory hierarchy currently looks like:

+ VERSION (version file)
+ x86_64/
    - bzero-ssm-agent.deb
    - bzero-ssm-agent.rpm
+ arm64/
    - bzero-ssm-agent.deb
    - bzero-ssm-agent.rpm