# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # An Azure Batch Task.

    # Batch will retry Tasks when a recovery operation is triggered on a Node.
    # Examples of recovery operations include (but are not limited to) when an
    # unhealthy Node is rebooted or a Compute Node disappeared due to host
    # failure. Retries due to recovery operations are independent of and are
    # not counted against the maxTaskRetryCount. Even if the maxTaskRetryCount
    # is 0, an internal retry due to a recovery operation may occur. Because of
    # this, all Tasks should be idempotent. This means Tasks need to tolerate
    # being interrupted and restarted without causing any corruption or
    # duplicate data. The best practice for long running Tasks is to use some
    # form of checkpointing.
    #
    class CloudTask

      include MsRestAzure

      # @return [String] A string that uniquely identifies the Task within the
      # Job. The ID can contain any combination of alphanumeric characters
      # including hyphens and underscores, and cannot contain more than 64
      # characters.
      attr_accessor :id

      # @return [String] A display name for the Task. The display name need not
      # be unique and can contain any Unicode characters up to a maximum length
      # of 1024.
      attr_accessor :display_name

      # @return [String] The URL of the Task.
      attr_accessor :url

      # @return [String] The ETag of the Task. This is an opaque string. You
      # can use it to detect whether the Task has changed between requests. In
      # particular, you can be pass the ETag when updating a Task to specify
      # that your changes should take effect only if nobody else has modified
      # the Task in the meantime.
      attr_accessor :e_tag

      # @return [DateTime] The last modified time of the Task.
      attr_accessor :last_modified

      # @return [DateTime] The creation time of the Task.
      attr_accessor :creation_time

      # @return [ExitConditions] How the Batch service should respond when the
      # Task completes.
      attr_accessor :exit_conditions

      # @return [TaskState] The current state of the Task. Possible values
      # include: 'active', 'preparing', 'running', 'completed'
      attr_accessor :state

      # @return [DateTime] The time at which the Task entered its current
      # state.
      attr_accessor :state_transition_time

      # @return [TaskState] The previous state of the Task. This property is
      # not set if the Task is in its initial Active state. Possible values
      # include: 'active', 'preparing', 'running', 'completed'
      attr_accessor :previous_state

      # @return [DateTime] The time at which the Task entered its previous
      # state. This property is not set if the Task is in its initial Active
      # state.
      attr_accessor :previous_state_transition_time

      # @return [String] The command line of the Task. For multi-instance
      # Tasks, the command line is executed as the primary Task, after the
      # primary Task and all subtasks have finished executing the coordination
      # command line. The command line does not run under a shell, and
      # therefore cannot take advantage of shell features such as environment
      # variable expansion. If you want to take advantage of such features, you
      # should invoke the shell in the command line, for example using "cmd /c
      # MyCommand" in Windows or "/bin/sh -c MyCommand" in Linux. If the
      # command line refers to file paths, it should use a relative path
      # (relative to the Task working directory), or use the Batch provided
      # environment variable
      # (https://docs.microsoft.com/en-us/azure/batch/batch-compute-node-environment-variables).
      attr_accessor :command_line

      # @return [TaskContainerSettings] The settings for the container under
      # which the Task runs. If the Pool that will run this Task has
      # containerConfiguration set, this must be set as well. If the Pool that
      # will run this Task doesn't have containerConfiguration set, this must
      # not be set. When this is specified, all directories recursively below
      # the AZ_BATCH_NODE_ROOT_DIR (the root of Azure Batch directories on the
      # node) are mapped into the container, all Task environment variables are
      # mapped into the container, and the Task command line is executed in the
      # container. Files produced in the container outside of
      # AZ_BATCH_NODE_ROOT_DIR might not be reflected to the host disk, meaning
      # that Batch file APIs will not be able to access those files.
      attr_accessor :container_settings

      # @return [Array<ResourceFile>] A list of files that the Batch service
      # will download to the Compute Node before running the command line. For
      # multi-instance Tasks, the resource files will only be downloaded to the
      # Compute Node on which the primary Task is executed. There is a maximum
      # size for the list of resource files.  When the max size is exceeded,
      # the request will fail and the response error code will be
      # RequestEntityTooLarge. If this occurs, the collection of ResourceFiles
      # must be reduced in size. This can be achieved using .zip files,
      # Application Packages, or Docker Containers.
      attr_accessor :resource_files

      # @return [Array<OutputFile>] A list of files that the Batch service will
      # upload from the Compute Node after running the command line. For
      # multi-instance Tasks, the files will only be uploaded from the Compute
      # Node on which the primary Task is executed.
      attr_accessor :output_files

      # @return [Array<EnvironmentSetting>] A list of environment variable
      # settings for the Task.
      attr_accessor :environment_settings

      # @return [AffinityInformation] A locality hint that can be used by the
      # Batch service to select a Compute Node on which to start the new Task.
      attr_accessor :affinity_info

      # @return [TaskConstraints] The execution constraints that apply to this
      # Task.
      attr_accessor :constraints

      # @return [UserIdentity] The user identity under which the Task runs. If
      # omitted, the Task runs as a non-administrative user unique to the Task.
      attr_accessor :user_identity

      # @return [TaskExecutionInformation] Information about the execution of
      # the Task.
      attr_accessor :execution_info

      # @return [ComputeNodeInformation] Information about the Compute Node on
      # which the Task ran.
      attr_accessor :node_info

      # @return [MultiInstanceSettings] An object that indicates that the Task
      # is a multi-instance Task, and contains information about how to run the
      # multi-instance Task.
      attr_accessor :multi_instance_settings

      # @return [TaskStatistics] Resource usage statistics for the Task.
      attr_accessor :stats

      # @return [TaskDependencies] The Tasks that this Task depends on. This
      # Task will not be scheduled until all Tasks that it depends on have
      # completed successfully. If any of those Tasks fail and exhaust their
      # retry counts, this Task will never be scheduled.
      attr_accessor :depends_on

      # @return [Array<ApplicationPackageReference>] A list of Packages that
      # the Batch service will deploy to the Compute Node before running the
      # command line. Application packages are downloaded and deployed to a
      # shared directory, not the Task working directory. Therefore, if a
      # referenced package is already on the Node, and is up to date, then it
      # is not re-downloaded; the existing copy on the Compute Node is used. If
      # a referenced Package cannot be installed, for example because the
      # package has been deleted or because download failed, the Task fails.
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


      #
      # Mapper for CloudTask class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'CloudTask',
          type: {
            name: 'Composite',
            class_name: 'CloudTask',
            model_properties: {
              id: {
                client_side_validation: true,
                required: false,
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
              url: {
                client_side_validation: true,
                required: false,
                serialized_name: 'url',
                type: {
                  name: 'String'
                }
              },
              e_tag: {
                client_side_validation: true,
                required: false,
                serialized_name: 'eTag',
                type: {
                  name: 'String'
                }
              },
              last_modified: {
                client_side_validation: true,
                required: false,
                serialized_name: 'lastModified',
                type: {
                  name: 'DateTime'
                }
              },
              creation_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'creationTime',
                type: {
                  name: 'DateTime'
                }
              },
              exit_conditions: {
                client_side_validation: true,
                required: false,
                serialized_name: 'exitConditions',
                type: {
                  name: 'Composite',
                  class_name: 'ExitConditions'
                }
              },
              state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'state',
                type: {
                  name: 'Enum',
                  module: 'TaskState'
                }
              },
              state_transition_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'stateTransitionTime',
                type: {
                  name: 'DateTime'
                }
              },
              previous_state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'previousState',
                type: {
                  name: 'Enum',
                  module: 'TaskState'
                }
              },
              previous_state_transition_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'previousStateTransitionTime',
                type: {
                  name: 'DateTime'
                }
              },
              command_line: {
                client_side_validation: true,
                required: false,
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
              affinity_info: {
                client_side_validation: true,
                required: false,
                serialized_name: 'affinityInfo',
                type: {
                  name: 'Composite',
                  class_name: 'AffinityInformation'
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
              user_identity: {
                client_side_validation: true,
                required: false,
                serialized_name: 'userIdentity',
                type: {
                  name: 'Composite',
                  class_name: 'UserIdentity'
                }
              },
              execution_info: {
                client_side_validation: true,
                required: false,
                serialized_name: 'executionInfo',
                type: {
                  name: 'Composite',
                  class_name: 'TaskExecutionInformation'
                }
              },
              node_info: {
                client_side_validation: true,
                required: false,
                serialized_name: 'nodeInfo',
                type: {
                  name: 'Composite',
                  class_name: 'ComputeNodeInformation'
                }
              },
              multi_instance_settings: {
                client_side_validation: true,
                required: false,
                serialized_name: 'multiInstanceSettings',
                type: {
                  name: 'Composite',
                  class_name: 'MultiInstanceSettings'
                }
              },
              stats: {
                client_side_validation: true,
                required: false,
                serialized_name: 'stats',
                type: {
                  name: 'Composite',
                  class_name: 'TaskStatistics'
                }
              },
              depends_on: {
                client_side_validation: true,
                required: false,
                serialized_name: 'dependsOn',
                type: {
                  name: 'Composite',
                  class_name: 'TaskDependencies'
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
              }
            }
          }
        }
      end
    end
  end
end
