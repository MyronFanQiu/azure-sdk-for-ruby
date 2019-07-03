# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::NetApp::Mgmt::V2019_05_01
  module Models
    #
    # Capacity pool resource
    #
    class CapacityPool

      include MsRestAzure

      # @return [String] Resource location
      attr_accessor :location

      # @return [String] Resource Id
      attr_accessor :id

      # @return [String] Resource name
      attr_accessor :name

      # @return [String] Resource type
      attr_accessor :type

      # @return Resource tags
      attr_accessor :tags

      # @return [String] poolId. UUID v4 used to identify the Pool
      attr_accessor :pool_id

      # @return [Integer] size. Provisioned size of the pool (in bytes).
      # Allowed values are in 4TiB chunks (value must be multiply of
      # 4398046511104). Default value: 4398046511104 .
      attr_accessor :size

      # @return [ServiceLevel] serviceLevel. The service level of the file
      # system. Possible values include: 'Standard', 'Premium', 'Ultra'.
      # Default value: 'Premium' .
      attr_accessor :service_level

      # @return [String] Azure lifecycle management
      attr_accessor :provisioning_state


      #
      # Mapper for CapacityPool class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'capacityPool',
          type: {
            name: 'Composite',
            class_name: 'CapacityPool',
            model_properties: {
              location: {
                client_side_validation: true,
                required: true,
                serialized_name: 'location',
                type: {
                  name: 'String'
                }
              },
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
              tags: {
                client_side_validation: true,
                required: false,
                serialized_name: 'tags',
                type: {
                  name: 'Object'
                }
              },
              pool_id: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'properties.poolId',
                constraints: {
                  MaxLength: 36,
                  MinLength: 36,
                  Pattern: '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'
                },
                type: {
                  name: 'String'
                }
              },
              size: {
                client_side_validation: true,
                required: true,
                serialized_name: 'properties.size',
                default_value: 4398046511104,
                constraints: {
                  InclusiveMaximum: 549755813888000,
                  InclusiveMinimum: 4398046511104
                },
                type: {
                  name: 'Number'
                }
              },
              service_level: {
                client_side_validation: true,
                required: true,
                serialized_name: 'properties.serviceLevel',
                default_value: 'Premium',
                type: {
                  name: 'String'
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
              }
            }
          }
        }
      end
    end
  end
end
