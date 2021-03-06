# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::TimeSeriesInsights::Mgmt::V2017_11_15
  module Models
    #
    # A reference data set provides metadata about the events in an
    # environment. Metadata in the reference data set will be joined with
    # events as they are read from event sources. The metadata that makes up
    # the reference data set is uploaded or modified through the Time Series
    # Insights data plane APIs.
    #
    class ReferenceDataSetResource < TrackedResource

      include MsRestAzure

      # @return [Array<ReferenceDataSetKeyProperty>] The list of key properties
      # for the reference data set.
      attr_accessor :key_properties

      # @return [DataStringComparisonBehavior] The reference data set key
      # comparison behavior can be set using this property. By default, the
      # value is 'Ordinal' - which means case sensitive key comparison will be
      # performed while joining reference data with events or while adding new
      # reference data. When 'OrdinalIgnoreCase' is set, case insensitive
      # comparison will be used. Possible values include: 'Ordinal',
      # 'OrdinalIgnoreCase'
      attr_accessor :data_string_comparison_behavior

      # @return [ProvisioningState] Provisioning state of the resource.
      # Possible values include: 'Accepted', 'Creating', 'Updating',
      # 'Succeeded', 'Failed', 'Deleting'
      attr_accessor :provisioning_state

      # @return [DateTime] The time the resource was created.
      attr_accessor :creation_time


      #
      # Mapper for ReferenceDataSetResource class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ReferenceDataSetResource',
          type: {
            name: 'Composite',
            class_name: 'ReferenceDataSetResource',
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
                required: true,
                serialized_name: 'location',
                type: {
                  name: 'String'
                }
              },
              tags: {
                client_side_validation: true,
                required: false,
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
              key_properties: {
                client_side_validation: true,
                required: true,
                serialized_name: 'properties.keyProperties',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ReferenceDataSetKeyPropertyElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ReferenceDataSetKeyProperty'
                      }
                  }
                }
              },
              data_string_comparison_behavior: {
                client_side_validation: true,
                required: false,
                serialized_name: 'properties.dataStringComparisonBehavior',
                type: {
                  name: 'Enum',
                  module: 'DataStringComparisonBehavior'
                }
              },
              provisioning_state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'properties.provisioningState',
                type: {
                  name: 'Enum',
                  module: 'ProvisioningState'
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
              }
            }
          }
        }
      end
    end
  end
end
