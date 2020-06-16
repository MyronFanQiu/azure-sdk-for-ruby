# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Monitor::Mgmt::V2015_05_01
  module Models
    #
    # Properties that define an Analytics item that is associated to an
    # Application Insights component.
    #
    class ApplicationInsightsComponentAnalyticsItem

      include MsRestAzure

      # @return [String] Internally assigned unique id of the item definition.
      attr_accessor :id

      # @return [String] The user-defined name of the item.
      attr_accessor :name

      # @return [String] The content of this item
      attr_accessor :content

      # @return [String] This instance's version of the data model. This can
      # change as new features are added.
      attr_accessor :version

      # @return [ItemScope] Enum indicating if this item definition is owned by
      # a specific user or is shared between all users with access to the
      # Application Insights component. Possible values include: 'shared',
      # 'user'
      attr_accessor :scope

      # @return [ItemType] Enum indicating the type of the Analytics item.
      # Possible values include: 'query', 'function', 'folder', 'recent'
      attr_accessor :type

      # @return [String] Date and time in UTC when this item was created.
      attr_accessor :time_created

      # @return [String] Date and time in UTC of the last modification that was
      # made to this item.
      attr_accessor :time_modified

      # @return [ApplicationInsightsComponentAnalyticsItemProperties]
      attr_accessor :properties


      #
      # Mapper for ApplicationInsightsComponentAnalyticsItem class as Ruby
      # Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ApplicationInsightsComponentAnalyticsItem',
          type: {
            name: 'Composite',
            class_name: 'ApplicationInsightsComponentAnalyticsItem',
            model_properties: {
              id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Id',
                type: {
                  name: 'String'
                }
              },
              name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Name',
                type: {
                  name: 'String'
                }
              },
              content: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Content',
                type: {
                  name: 'String'
                }
              },
              version: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'Version',
                type: {
                  name: 'String'
                }
              },
              scope: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Scope',
                type: {
                  name: 'String'
                }
              },
              type: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Type',
                type: {
                  name: 'String'
                }
              },
              time_created: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'TimeCreated',
                type: {
                  name: 'String'
                }
              },
              time_modified: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'TimeModified',
                type: {
                  name: 'String'
                }
              },
              properties: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Properties',
                type: {
                  name: 'Composite',
                  class_name: 'ApplicationInsightsComponentAnalyticsItemProperties'
                }
              }
            }
          }
        }
      end
    end
  end
end