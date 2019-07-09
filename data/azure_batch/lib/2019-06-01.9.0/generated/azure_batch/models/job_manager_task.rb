# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # Specifies details of a Job Manager Task.

    # The Job Manager Task is automatically started when the Job is created.
    # The Batch service tries to schedule the Job Manager Task before any other
    # Tasks in the Job. When shrinking a Pool, the Batch service tries to
    # preserve Nodes where Job Manager Tasks are running for as long as
    # possible (that is, Compute Nodes running 'normal' Tasks are removed
    # before Compute Nodes running Job Manager Tasks). When a Job Manager Task
    # fails and needs to be restarted, the system tries to schedule it at the
    # highest priority. If there are no idle Compute Nodes available, the
    # system may terminate one of the running Tasks in the Pool and return it
    # to the queue in order to make room for the Job Manager Task to restart.
    # Note that a Job Manager Task in one Job does not have priority over Tasks
    # in other Jobs. Across Jobs, only Job level priorities are observed. For
    # example, if a Job Manager in a priority 0 Job needs to be restarted, it
    # will not displace Tasks of a priority 1 Job. Batch will retry Tasks when
    # a recovery operation is triggered on a Node. Examples of recovery
    # operations include (but are not limited to) when an unhealthy Node is
    # rebooted or a Compute Node disappeared due to host failure. Retries due
    # to recovery operations are independent of and are not counted against the
    # maxTaskRetryCount. Even if the maxTaskRetryCount is 0, an internal retry
    # due to a recovery operation may occur. Because of this, all Tasks should
    # be idempotent. This means Tasks need to tolerate being interrupted and
    # restarted without causing any corruption or duplicate data. The best
    # practice for long running Tasks is to use some form of checkpointing.
    #
    class JobManagerTask

      include MsRestAzure

      # @return [String] A string that uniquely identifies the Job Manager Task
      # within the Job. The ID can contain any combination of alphanumeric
      # characters including hyphens and underscores and cannot contain more
      # than 64 characters.
      attr_accessor :id

      # @return [String] The display name of the Job Manager Task. It need not
      # be unique and can contain any Unicode characters up to a maximum length
      # of 1024.
      attr_accessor :display_name

      # @return [String] The command line of the Job Manager Task. The command
      # line does not run under a shell, and therefore cannot take advantage of
      # shell features such as environment variable expansion. If you want to
      # take advantage of such features, you should invoke the shell in the
      # command line, for example using "cmd /c MyCommand" in Windows or
      # "/bin/sh -c MyCommand" in Linux. If the command line refers to file
      # paths, it should use a relative path (relative to the Task working
      # directory), or use the Batch provided environment variable
      # (https://docs.microsoft.com/en-us/azure/batch/batch-compute-node-environment-variables).
      attr_accessor :command_line

      # @return [TaskContainerSettings] The settings for the container under
      # which the Job Manager Task runs. If the Pool that will run this Task
      # has containerConfiguration set, this must be set as well. If the Pool
      # that will run this Task doesn't have containerConfiguration set, this
      # must not be set. When this is specified, all directories recursively
      # below the AZ_BATCH_NODE_ROOT_DIR (the root of Azure Batch directories
      # on the node) are mapped into the container, all Task environment
      # variables are mapped into the container, and the Task command line is
      # executed in the container. Files produced in the container outside of
      # AZ_BATCH_NODE_ROOT_DIR might not be reflected to the host disk, meaning
      # that Batch file APIs will not be able to access those files.
      attr_accessor :container_settings

      # @return [Array<ResourceFile>] A list of files that the Batch service
      # will download to the Compute Node before running the command line.
      # Files listed under this element are located in the Task's working
      # directory. There is a maximum size for the list of resource files.
      # When the max size is exceeded, the request will fail and the response
      # error code will be RequestEntityTooLarge. If this occurs, the
      # collection of ResourceFiles must be reduced in size. This can be
      # achieved using .zip files, Application Packages, or Docker Containers.
      attr_accessor :resource_files

      # @return [Array<OutputFile>] A list of files that the Batch service will
      # upload from the Compute Node after running the command line. For
      # multi-instance Tasks, the files will only be uploaded from the Compute
      # Node on which the primary Task is executed.
      attr_accessor :output_files

      # @return [Array<EnvironmentSetting>] A list of environment variable
      # settings for the Job Manager Task.
      attr_accessor :environment_settings

      # @return [TaskConstraints] Constraints that apply to the Job Manager
      # Task.
      attr_accessor :constraints

      # @return [Boolean] Whether completion of the Job Manager Task signifies
      # completion of the entire Job. If true, when the Job Manager Task
      # completes, the Batch service marks the Job as complete. If any Tasks
      # are still running at this time (other than Job Release), those Tasks
      # are terminated. If false, the completion of the Job Manager Task does
      # not affect the Job status. In this case, you should either use the
      # onAllTasksComplete attribute to terminate the Job, or have a client or
      # user terminate the Job explicitly. An example of this is if the Job
      # Manager creates a set of Tasks but then takes no further role in their
      # execution. The default value is true. If you are using the
      # onAllTasksComplete and onTaskFailure attributes to control Job
      # lifetime, and using the Job Manager Task only to create the Tasks for
      # the Job (not to monitor progress), then it is important to set
      # killJobOnCompletion to false.
      attr_accessor :kill_job_on_completion

      # @return [UserIdentity] The user identity under which the Job Manager
      # Task runs. If omitted, the Task runs as a non-administrative user
      # unique to the Task.
      attr_accessor :user_identity

      # @return [Boolean] Whether the Job Manager Task requires exclusive use
      # of the Compute Node where it runs. If true, no other Tasks will run on
      # the same Node for as long as the Job Manager is running. If false,
      # other Tasks can run simultaneously with the Job Manager on a Compute
      # Node. The Job Manager Task counts normally against the Compute Node's
      # concurrent Task limit, so this is only relevant if the Compute Node
      # allows multiple concurrent Tasks. The default value is true.
      attr_accessor :run_exclusive

      # @return [Array<ApplicationPackageReference>] A list of Application
      # Packages that the Batch service will deploy to the Compute Node before
      # running the command line. Application Packages are downloaded and
      # deployed to a shared directory, not the Task working directory.
      # Therefore, if a referenced Application Package is already on the
      # Compute Node, and is up to date, then it is not re-downloaded; the
      # existing copy on the Compute Node is used. If a referenced Application
      # Package cannot be installed, for example because the package has been
      # deleted or because download failed, the Task fails.
      attr_accessor :application_package_references

      # @return [AuthenticationTokenSettings] The settings for an
      # authentication token that the Task can use to perform Batch service
      # operations. If this property is set, the Batch service provides the
      # Task with an authentication token which can be used to authenticate
      # Batch service operations without requiring an Account access key. The
      # token is provided via the AZ_BATCH_AUTHENTICATION_TOKEN environment
      # variable. The operations that the Task can carry out using the token
      # depend on the settings. For example, a Task can request Job permissions
      # in order to add other Tasks to the Job, or check the status of the Job
      # or of other Tasks under the Job.
      attr_accessor :authentication_token_settings

      # @return [Boolean] Whether the Job Manager Task may run on a
      # low-priority Compute Node. The default value is true.
      attr_accessor :allow_low_priority_node


      #
      # Mapper for JobManagerTask class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobManagerTask',
          type: {
            name: 'Composite',
            class_name: 'JobManagerTask',
            model_properties: {
              id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              },
              display_name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'displayName',
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
              output_files: {
                client_side_validation: true,
                required: false,
                serialized_name: 'outputFiles',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'OutputFileElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'OutputFile'
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
              constraints: {
                client_side_validation: true,
                required: false,
                serialized_name: 'constraints',
                type: {
                  name: 'Composite',
                  class_name: 'TaskConstraints'
                }
              },
              kill_job_on_completion: {
                client_side_validation: true,
                required: false,
                serialized_name: 'killJobOnCompletion',
                type: {
                  name: 'Boolean'
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
              },
              run_exclusive: {
                client_side_validation: true,
                required: false,
                serialized_name: 'runExclusive',
                type: {
                  name: 'Boolean'
                }
              },
              application_package_references: {
                client_side_validation: true,
                required: false,
                serialized_name: 'applicationPackageReferences',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ApplicationPackageReferenceElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ApplicationPackageReference'
                      }
                  }
                }
              },
              authentication_token_settings: {
                client_side_validation: true,
                required: false,
                serialized_name: 'authenticationTokenSettings',
                type: {
                  name: 'Composite',
                  class_name: 'AuthenticationTokenSettings'
                }
              },
              allow_low_priority_node: {
                client_side_validation: true,
                required: false,
                serialized_name: 'allowLowPriorityNode',
                type: {
                  name: 'Boolean'
                }
              }
            }
          }
        }
      end
    end
  end
end