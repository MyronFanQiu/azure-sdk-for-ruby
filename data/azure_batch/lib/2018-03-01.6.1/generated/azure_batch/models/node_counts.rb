# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # The number of nodes in each node state.
    #
    #
    class NodeCounts

      include MsRestAzure

      # @return [Integer] The number of nodes in the creating state.
      attr_accessor :creating

      # @return [Integer] The number of nodes in the idle state.
      attr_accessor :idle

      # @return [Integer] The number of nodes in the offline state.
      attr_accessor :offline

      # @return [Integer] The number of nodes in the preempted state.
      attr_accessor :preempted

      # @return [Integer] The count of nodes in the rebooting state.
      attr_accessor :rebooting

      # @return [Integer] The number of nodes in the reimaging state.
      attr_accessor :reimaging

      # @return [Integer] The number of nodes in the running state.
      attr_accessor :running

      # @return [Integer] The number of nodes in the starting state.
      attr_accessor :starting

      # @return [Integer] The number of nodes in the startTaskFailed state.
      attr_accessor :start_task_failed

      # @return [Integer] The number of nodes in the leavingPool state.
      attr_accessor :leaving_pool

      # @return [Integer] The number of nodes in the unknown state.
      attr_accessor :unknown

      # @return [Integer] The number of nodes in the unusable state.
      attr_accessor :unusable

      # @return [Integer] The number of nodes in the waitingForStartTask state.
      attr_accessor :waiting_for_start_task

      # @return [Integer] The total number of nodes.
      attr_accessor :total


      #
      # Mapper for NodeCounts class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'NodeCounts',
          type: {
            name: 'Composite',
            class_name: 'NodeCounts',
            model_properties: {
              creating: {
                client_side_validation: true,
                required: true,
                serialized_name: 'creating',
                type: {
                  name: 'Number'
                }
              },
              idle: {
                client_side_validation: true,
                required: true,
                serialized_name: 'idle',
                type: {
                  name: 'Number'
                }
              },
              offline: {
                client_side_validation: true,
                required: true,
                serialized_name: 'offline',
                type: {
                  name: 'Number'
                }
              },
              preempted: {
                client_side_validation: true,
                required: true,
                serialized_name: 'preempted',
                type: {
                  name: 'Number'
                }
              },
              rebooting: {
                client_side_validation: true,
                required: true,
                serialized_name: 'rebooting',
                type: {
                  name: 'Number'
                }
              },
              reimaging: {
                client_side_validation: true,
                required: true,
                serialized_name: 'reimaging',
                type: {
                  name: 'Number'
                }
              },
              running: {
                client_side_validation: true,
                required: true,
                serialized_name: 'running',
                type: {
                  name: 'Number'
                }
              },
              starting: {
                client_side_validation: true,
                required: true,
                serialized_name: 'starting',
                type: {
                  name: 'Number'
                }
              },
              start_task_failed: {
                client_side_validation: true,
                required: true,
                serialized_name: 'startTaskFailed',
                type: {
                  name: 'Number'
                }
              },
              leaving_pool: {
                client_side_validation: true,
                required: true,
                serialized_name: 'leavingPool',
                type: {
                  name: 'Number'
                }
              },
              unknown: {
                client_side_validation: true,
                required: true,
                serialized_name: 'unknown',
                type: {
                  name: 'Number'
                }
              },
              unusable: {
                client_side_validation: true,
                required: true,
                serialized_name: 'unusable',
                type: {
                  name: 'Number'
                }
              },
              waiting_for_start_task: {
                client_side_validation: true,
                required: true,
                serialized_name: 'waitingForStartTask',
                type: {
                  name: 'Number'
                }
              },
              total: {
                client_side_validation: true,
                required: true,
                serialized_name: 'total',
                type: {
                  name: 'Number'
                }
              }
            }
          }
        }
      end
    end
  end
end
