# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::BatchAI::Mgmt::V2018_05_01
  module Models
    #
    # Batch AI Workspace information.
    #
    class Workspace < Resource

      include MsRestAzure

      # @return [DateTime] Creation time. Time when the Workspace was created.
      attr_accessor :creation_time

      # @return [ProvisioningState] Provisioning state. The provisioned state
      # of the Workspace. Possible values include: 'creating', 'succeeded',
      # 'failed', 'deleting'
      attr_accessor :provisioning_state

      # @return [DateTime] Provisioning state transition time. The time at
      # which the workspace entered its current provisioning state.
      attr_accessor :provisioning_state_transition_time


      #
      # Mapper for Workspace class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'Workspace',
          type: {
            name: 'Composite',
            class_name: 'Workspace',
            model_properties: {
              id: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              },
              name: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              type: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'type',
                type: {
                  name: 'String'
                }
              },
              location: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'location',
                type: {
                  name: 'String'
                }
              },
              tags: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'tags',
                type: {
                  name: 'Dictionary',
                  value: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'StringElementType',
                      type: {
                        name: 'String'
                      }
                  }
                }
              },
              creation_time: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'properties.creationTime',
                type: {
                  name: 'DateTime'
                }
              },
              provisioning_state: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'properties.provisioningState',
                type: {
                  name: 'String'
                }
              },
              provisioning_state_transition_time: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'properties.provisioningStateTransitionTime',
                type: {
                  name: 'DateTime'
                }
              }
            }
          }
        }
      end
    end
  end
end