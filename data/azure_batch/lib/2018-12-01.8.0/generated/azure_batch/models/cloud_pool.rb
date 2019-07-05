# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # A pool in the Azure Batch service.
    #
    #
    class CloudPool

      include MsRestAzure

      # @return [String] A string that uniquely identifies the pool within the
      # account. The ID can contain any combination of alphanumeric characters
      # including hyphens and underscores, and cannot contain more than 64
      # characters. The ID is case-preserving and case-insensitive (that is,
      # you may not have two IDs within an account that differ only by case).
      attr_accessor :id

      # @return [String] The display name for the pool. The display name need
      # not be unique and can contain any Unicode characters up to a maximum
      # length of 1024.
      attr_accessor :display_name

      # @return [String] The URL of the pool.
      attr_accessor :url

      # @return [String] The ETag of the pool. This is an opaque string. You
      # can use it to detect whether the pool has changed between requests. In
      # particular, you can be pass the ETag when updating a pool to specify
      # that your changes should take effect only if nobody else has modified
      # the pool in the meantime.
      attr_accessor :e_tag

      # @return [DateTime] The last modified time of the pool. This is the last
      # time at which the pool level data, such as the targetDedicatedNodes or
      # enableAutoscale settings, changed. It does not factor in node-level
      # changes such as a compute node changing state.
      attr_accessor :last_modified

      # @return [DateTime] The creation time of the pool.
      attr_accessor :creation_time

      # @return [PoolState] The current state of the pool. Possible values
      # include: 'active', 'deleting'
      attr_accessor :state

      # @return [DateTime] The time at which the pool entered its current
      # state.
      attr_accessor :state_transition_time

      # @return [AllocationState] Whether the pool is resizing. Possible values
      # include: 'steady', 'resizing', 'stopping'
      attr_accessor :allocation_state

      # @return [DateTime] The time at which the pool entered its current
      # allocation state.
      attr_accessor :allocation_state_transition_time

      # @return [String] The size of virtual machines in the pool. All virtual
      # machines in a pool are the same size. For information about available
      # sizes of virtual machines in pools, see Choose a VM size for compute
      # nodes in an Azure Batch pool
      # (https://docs.microsoft.com/azure/batch/batch-pool-vm-sizes).
      attr_accessor :vm_size

      # @return [CloudServiceConfiguration] The cloud service configuration for
      # the pool. This property and virtualMachineConfiguration are mutually
      # exclusive and one of the properties must be specified. This property
      # cannot be specified if the Batch account was created with its
      # poolAllocationMode property set to 'UserSubscription'.
      attr_accessor :cloud_service_configuration

      # @return [VirtualMachineConfiguration] The virtual machine configuration
      # for the pool. This property and cloudServiceConfiguration are mutually
      # exclusive and one of the properties must be specified.
      attr_accessor :virtual_machine_configuration

      # @return [Duration] The timeout for allocation of compute nodes to the
      # pool. This is the timeout for the most recent resize operation. (The
      # initial sizing when the pool is created counts as a resize.) The
      # default value is 15 minutes.
      attr_accessor :resize_timeout

      # @return [Array<ResizeError>] A list of errors encountered while
      # performing the last resize on the pool. This property is set only if
      # one or more errors occurred during the last pool resize, and only when
      # the pool allocationState is Steady.
      attr_accessor :resize_errors

      # @return [Integer] The number of dedicated compute nodes currently in
      # the pool.
      attr_accessor :current_dedicated_nodes

      # @return [Integer] The number of low-priority compute nodes currently in
      # the pool. Low-priority compute nodes which have been preempted are
      # included in this count.
      attr_accessor :current_low_priority_nodes

      # @return [Integer] The desired number of dedicated compute nodes in the
      # pool.
      attr_accessor :target_dedicated_nodes

      # @return [Integer] The desired number of low-priority compute nodes in
      # the pool.
      attr_accessor :target_low_priority_nodes

      # @return [Boolean] Whether the pool size should automatically adjust
      # over time. If false, at least one of targetDedicateNodes and
      # targetLowPriorityNodes must be specified. If true, the autoScaleFormula
      # property is required and the pool automatically resizes according to
      # the formula. The default value is false.
      attr_accessor :enable_auto_scale

      # @return [String] A formula for the desired number of compute nodes in
      # the pool. This property is set only if the pool automatically scales,
      # i.e. enableAutoScale is true.
      attr_accessor :auto_scale_formula

      # @return [Duration] The time interval at which to automatically adjust
      # the pool size according to the autoscale formula. This property is set
      # only if the pool automatically scales, i.e. enableAutoScale is true.
      attr_accessor :auto_scale_evaluation_interval

      # @return [AutoScaleRun] The results and errors from the last execution
      # of the autoscale formula. This property is set only if the pool
      # automatically scales, i.e. enableAutoScale is true.
      attr_accessor :auto_scale_run

      # @return [Boolean] Whether the pool permits direct communication between
      # nodes. This imposes restrictions on which nodes can be assigned to the
      # pool. Specifying this value can reduce the chance of the requested
      # number of nodes to be allocated in the pool.
      attr_accessor :enable_inter_node_communication

      # @return [NetworkConfiguration] The network configuration for the pool.
      attr_accessor :network_configuration

      # @return [StartTask] A task specified to run on each compute node as it
      # joins the pool.
      attr_accessor :start_task

      # @return [Array<CertificateReference>] The list of certificates to be
      # installed on each compute node in the pool. For Windows compute nodes,
      # the Batch service installs the certificates to the specified
      # certificate store and location. For Linux compute nodes, the
      # certificates are stored in a directory inside the task working
      # directory and an environment variable AZ_BATCH_CERTIFICATES_DIR is
      # supplied to the task to query for this location. For certificates with
      # visibility of 'remoteUser', a 'certs' directory is created in the
      # user's home directory (e.g., /home/{user-name}/certs) and certificates
      # are placed in that directory.
      attr_accessor :certificate_references

      # @return [Array<ApplicationPackageReference>] The list of application
      # packages to be installed on each compute node in the pool. Changes to
      # application package references affect all new compute nodes joining the
      # pool, but do not affect compute nodes that are already in the pool
      # until they are rebooted or reimaged. There is a maximum of 10
      # application package references on any given pool.
      attr_accessor :application_package_references

      # @return [Array<String>] The list of application licenses the Batch
      # service will make available on each compute node in the pool. The list
      # of application licenses must be a subset of available Batch service
      # application licenses. If a license is requested which is not supported,
      # pool creation will fail.
      attr_accessor :application_licenses

      # @return [Integer] The maximum number of tasks that can run concurrently
      # on a single compute node in the pool. The default value is 1. The
      # maximum value is the smaller of 4 times the number of cores of the
      # vmSize of the pool or 256.
      attr_accessor :max_tasks_per_node

      # @return [TaskSchedulingPolicy] How tasks are distributed across compute
      # nodes in a pool. If not specified, the default is spread.
      attr_accessor :task_scheduling_policy

      # @return [Array<UserAccount>] The list of user accounts to be created on
      # each node in the pool.
      attr_accessor :user_accounts

      # @return [Array<MetadataItem>] A list of name-value pairs associated
      # with the pool as metadata.
      attr_accessor :metadata

      # @return [PoolStatistics] Utilization and resource usage statistics for
      # the entire lifetime of the pool. This property is populated only if the
      # CloudPool was retrieved with an expand clause including the 'stats'
      # attribute; otherwise it is null. The statistics may not be immediately
      # available. The Batch service performs periodic roll-up of statistics.
      # The typical delay is about 30 minutes.
      attr_accessor :stats


      #
      # Mapper for CloudPool class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'CloudPool',
          type: {
            name: 'Composite',
            class_name: 'CloudPool',
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
              state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'state',
                type: {
                  name: 'Enum',
                  module: 'PoolState'
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
              allocation_state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'allocationState',
                type: {
                  name: 'Enum',
                  module: 'AllocationState'
                }
              },
              allocation_state_transition_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'allocationStateTransitionTime',
                type: {
                  name: 'DateTime'
                }
              },
              vm_size: {
                client_side_validation: true,
                required: false,
                serialized_name: 'vmSize',
                type: {
                  name: 'String'
                }
              },
              cloud_service_configuration: {
                client_side_validation: true,
                required: false,
                serialized_name: 'cloudServiceConfiguration',
                type: {
                  name: 'Composite',
                  class_name: 'CloudServiceConfiguration'
                }
              },
              virtual_machine_configuration: {
                client_side_validation: true,
                required: false,
                serialized_name: 'virtualMachineConfiguration',
                type: {
                  name: 'Composite',
                  class_name: 'VirtualMachineConfiguration'
                }
              },
              resize_timeout: {
                client_side_validation: true,
                required: false,
                serialized_name: 'resizeTimeout',
                type: {
                  name: 'TimeSpan'
                }
              },
              resize_errors: {
                client_side_validation: true,
                required: false,
                serialized_name: 'resizeErrors',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ResizeErrorElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ResizeError'
                      }
                  }
                }
              },
              current_dedicated_nodes: {
                client_side_validation: true,
                required: false,
                serialized_name: 'currentDedicatedNodes',
                type: {
                  name: 'Number'
                }
              },
              current_low_priority_nodes: {
                client_side_validation: true,
                required: false,
                serialized_name: 'currentLowPriorityNodes',
                type: {
                  name: 'Number'
                }
              },
              target_dedicated_nodes: {
                client_side_validation: true,
                required: false,
                serialized_name: 'targetDedicatedNodes',
                type: {
                  name: 'Number'
                }
              },
              target_low_priority_nodes: {
                client_side_validation: true,
                required: false,
                serialized_name: 'targetLowPriorityNodes',
                type: {
                  name: 'Number'
                }
              },
              enable_auto_scale: {
                client_side_validation: true,
                required: false,
                serialized_name: 'enableAutoScale',
                type: {
                  name: 'Boolean'
                }
              },
              auto_scale_formula: {
                client_side_validation: true,
                required: false,
                serialized_name: 'autoScaleFormula',
                type: {
                  name: 'String'
                }
              },
              auto_scale_evaluation_interval: {
                client_side_validation: true,
                required: false,
                serialized_name: 'autoScaleEvaluationInterval',
                type: {
                  name: 'TimeSpan'
                }
              },
              auto_scale_run: {
                client_side_validation: true,
                required: false,
                serialized_name: 'autoScaleRun',
                type: {
                  name: 'Composite',
                  class_name: 'AutoScaleRun'
                }
              },
              enable_inter_node_communication: {
                client_side_validation: true,
                required: false,
                serialized_name: 'enableInterNodeCommunication',
                type: {
                  name: 'Boolean'
                }
              },
              network_configuration: {
                client_side_validation: true,
                required: false,
                serialized_name: 'networkConfiguration',
                type: {
                  name: 'Composite',
                  class_name: 'NetworkConfiguration'
                }
              },
              start_task: {
                client_side_validation: true,
                required: false,
                serialized_name: 'startTask',
                type: {
                  name: 'Composite',
                  class_name: 'StartTask'
                }
              },
              certificate_references: {
                client_side_validation: true,
                required: false,
                serialized_name: 'certificateReferences',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'CertificateReferenceElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'CertificateReference'
                      }
                  }
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
              application_licenses: {
                client_side_validation: true,
                required: false,
                serialized_name: 'applicationLicenses',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'StringElementType',
                      type: {
                        name: 'String'
                      }
                  }
                }
              },
              max_tasks_per_node: {
                client_side_validation: true,
                required: false,
                serialized_name: 'maxTasksPerNode',
                type: {
                  name: 'Number'
                }
              },
              task_scheduling_policy: {
                client_side_validation: true,
                required: false,
                serialized_name: 'taskSchedulingPolicy',
                type: {
                  name: 'Composite',
                  class_name: 'TaskSchedulingPolicy'
                }
              },
              user_accounts: {
                client_side_validation: true,
                required: false,
                serialized_name: 'userAccounts',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'UserAccountElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'UserAccount'
                      }
                  }
                }
              },
              metadata: {
                client_side_validation: true,
                required: false,
                serialized_name: 'metadata',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'MetadataItemElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'MetadataItem'
                      }
                  }
                }
              },
              stats: {
                client_side_validation: true,
                required: false,
                serialized_name: 'stats',
                type: {
                  name: 'Composite',
                  class_name: 'PoolStatistics'
                }
              }
            }
          }
        }
      end
    end
  end
end
