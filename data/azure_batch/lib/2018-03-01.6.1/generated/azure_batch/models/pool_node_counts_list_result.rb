# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # Model object.
    #
    class PoolNodeCountsListResult

      include MsRestAzure

      include MsRest::JSONable
      # @return [Array<PoolNodeCounts>] A list of node counts by pool.
      attr_accessor :value

      # @return [String]
      attr_accessor :odatanext_link

      # return [Proc] with next page method call.
      attr_accessor :next_method

      #
      # Gets the rest of the items for the request, enabling auto-pagination.
      #
      # @return [Array<PoolNodeCounts>] operation results.
      #
      def get_all_items
        items = @value
        page = self
        while page.odatanext_link != nil && !page.odatanext_link.strip.empty? do
          page = page.get_next_page
          items.concat(page.value)
        end
        items
      end

      #
      # Gets the next page of results.
      #
      # @return [PoolNodeCountsListResult] with next page content.
      #
      def get_next_page
        response = @next_method.call(@odatanext_link).value! unless @next_method.nil?
        unless response.nil?
          @odatanext_link = response.body.odatanext_link
          @value = response.body.value
          self
        end
      end

      #
      # Mapper for PoolNodeCountsListResult class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'PoolNodeCountsListResult',
          type: {
            name: 'Composite',
            class_name: 'PoolNodeCountsListResult',
            model_properties: {
              value: {
                client_side_validation: true,
                required: false,
                serialized_name: 'value',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'PoolNodeCountsElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'PoolNodeCounts'
                      }
                  }
                }
              },
              odatanext_link: {
                client_side_validation: true,
                required: false,
                serialized_name: 'odata\\.nextLink',
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
