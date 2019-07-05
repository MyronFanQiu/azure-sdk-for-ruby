# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # A Job Release task to run on job completion on any compute node where the
    # job has run.

    # The Job Release task runs when the job ends, because of one of the
    # following: The user calls the Terminate Job API, or the Delete Job API
    # while the job is still active, the job's maximum wall clock time
    # constraint is reached, and the job is still active, or the job's Job
    # Manager task completed, and the job is configured to terminate when the
    # Job Manager completes. The Job Release task runs on each compute node
    # where tasks of the job have run and the Job Preparation task ran and
    # completed. If you reimage a compute node after it has run the Job
    # Preparation task, and the job ends without any further tasks of the job
    # running on that compute node (and hence the Job Preparation task does not
    # re-run), then the Job Release task does not run on that node. If a
    # compute node reboots while the Job Release task is still running, the Job
    # Release task runs again when the compute node starts up. The job is not
    # marked as complete until all Job Release tasks have completed. The Job
    # Release task runs in the background. It does not occupy a scheduling
    # slot; that is, it does not count towards the maxTasksPerNode limit
    # specified on the pool.
    #
    class JobReleaseTask

      include MsRestAzure

      # @return [String] A string that uniquely identifies the Job Release task
      # within the job. The ID can contain any combination of alphanumeric
      # characters including hyphens and underscores and cannot contain more
      # than 64 characters. If you do not specify this property, the Batch
      # service assigns a default value of 'jobrelease'. No other task in the
      # job can have the same ID as the Job Release task. If you try to submit
      # a task with the same id, the Batch service rejects the request with
      # error code TaskIdSameAsJobReleaseTask; if you are calling the REST API
      # directly, the HTTP status code is 409 (Conflict).
      attr_accessor :id

      # @return [String] The command line of the Job Release task. The command
      # line does not run under a shell, and therefore cannot take advantage of
      # shell features such as environment variable expansion. If you want to
      # take advantage of such features, you should invoke the shell in the
      # command line, for example using "cmd /c MyCommand" in Windows or
      # "/bin/sh -c MyCommand" in Linux. If the command line refers to file
      # paths, it should use a relative path (relative to the task working
      # directory), or use the Batch provided environment variable
      # (https://docs.microsoft.com/en-us/azure/batch/batch-compute-node-environment-variables).
      attr_accessor :command_line

      # @return [TaskContainerSettings] The settings for the container under
      # which the Job Release task runs. When this is specified, all
      # directories recursively below the AZ_BATCH_NODE_ROOT_DIR (the root of
      # Azure Batch directories on the node) are mapped into the container, all
      # task environment variables are mapped into the container, and the task
      # command line is executed in the container.
      attr_accessor :container_settings

      # @return [Array<ResourceFile>] A list of files that the Batch service
      # will download to the compute node before running the command line.
      # There is a maximum size for the list of resource files.  When the max
      # size is exceeded, the request will fail and the response error code
      # will be RequestEntityTooLarge. If this occurs, the collection of
      # ResourceFiles must be reduced in size. This can be achieved using .zip
      # files, Application Packages, or Docker Containers. Files listed under
      # this element are located in the task's working directory.
      attr_accessor :resource_files

      # @return [Array<EnvironmentSetting>] A list of environment variable
      # settings for the Job Release task.
      attr_accessor :environment_settings

      # @return [Duration] The maximum elapsed time that the Job Release task
      # may run on a given compute node, measured from the time the task
      # starts. If the task does not complete within the time limit, the Batch
      # service terminates it. The default value is 15 minutes. You may not
      # specify a timeout longer than 15 minutes. If you do, the Batch service
      # rejects it with an error; if you are calling the REST API directly, the
      # HTTP status code is 400 (Bad Request).
      attr_accessor :max_wall_clock_time

      # @return [Duration] The minimum time to retain the task directory for
      # the Job Release task on the compute node. After this time, the Batch
      # service may delete the task directory and all its contents. The default
      # is infinite, i.e. the task directory will be retained until the compute
      # node is removed or reimaged.
      attr_accessor :retention_time

      # @return [UserIdentity] The user identity under which the Job Release
      # task runs. If omitted, the task runs as a non-administrative user
      # unique to the task.
      attr_accessor :user_identity


      #
      # Mapper for JobReleaseTask class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobReleaseTask',
          type: {
            name: 'Composite',
            class_name: 'JobReleaseTask',
            model_properties: {
              id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              },
              command_line: {
                client_side_validation: true,
                required: true,
                serialized_name: 'commandLine',
                type: {
                  name: 'String'
                }
              },
              container_settings: {
                client_side_validation: true,
                required: false,
                serialized_name: 'containerSettings',
                type: {
                  name: 'Composite',
                  class_name: 'TaskContainerSettings'
                }
              },
              resource_files: {
                client_side_validation: true,
                required: false,
                serialized_name: 'resourceFiles',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ResourceFileElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ResourceFile'
                      }
                  }
                }
              },
              environment_settings: {
                client_side_validation: true,
                required: false,
                serialized_name: 'environmentSettings',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'EnvironmentSettingElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'EnvironmentSetting'
                      }
                  }
                }
              },
              max_wall_clock_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'maxWallClockTime',
                type: {
                  name: 'TimeSpan'
                }
              },
              retention_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'retentionTime',
                type: {
                  name: 'TimeSpan'
                }
              },
              user_identity: {
                client_side_validation: true,
                required: false,
                serialized_name: 'userIdentity',
                type: {
                  name: 'Composite',
                  class_name: 'UserIdentity'
                }
              }
            }
          }
        }
      end
    end
  end
end
